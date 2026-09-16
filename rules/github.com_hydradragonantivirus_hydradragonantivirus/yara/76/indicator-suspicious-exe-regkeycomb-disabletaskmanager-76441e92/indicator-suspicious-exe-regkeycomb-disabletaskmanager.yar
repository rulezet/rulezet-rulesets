rule INDICATOR_SUSPICIOUS_EXE_RegKeyComb_DisableTaskManager {
    meta:
        author = "ditekSHen"
        description = "Detects executables embedding registry key / value combination indicative of disabling task manager"
    strings:
        $r1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide nocase
        $r2 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide nocase
        $k1 = "DisableTaskMgr" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and (1 of ($r*) and 1 of ($k*))
}