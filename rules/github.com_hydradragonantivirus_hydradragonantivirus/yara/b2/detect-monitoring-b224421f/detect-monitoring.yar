rule Detect_Monitoring 
{
    meta:
	author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
	description = "Check for monitoring tools"
    strings:
        $var1 = "procexp.exe" nocase
        $var2 = "fiddler.exe" nocase
        $var3 = "winhex.exe" nocase      
        $var4 = "procmon.exe" nocase
        $var5 = "processmonitor.exe" nocase
        $var6 = "wireshark.exe" nocase
        $var7 = "processhacker.exe" nocase
        $var8 = "hiew32.exe" nocase

        $reg = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $val = "DisableTaskMgr" 

    condition:
        any of ($var*) or $reg and $val
}