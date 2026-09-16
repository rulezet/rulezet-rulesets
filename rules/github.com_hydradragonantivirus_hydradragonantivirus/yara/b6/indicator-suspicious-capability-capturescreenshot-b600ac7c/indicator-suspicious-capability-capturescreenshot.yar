rule INDICATOR_SUSPICIOUS_CAPABILITY_CaptureScreenShot {
    meta:
        author = "ditekSHen"
        description = "Detects .NET executables with screen capture cabability"
    strings:
        $dll = "gdiplus.dll" ascii wide nocase
        $c1 = "gdipcreatebitmapfromhbitmap" ascii wide nocase
        $c2 = "gdipcreatebitmapfromscan0" ascii wide nocase
        $save = "gdipsaveimagetofile" ascii wide nocase
    condition:
         uint16(0) == 0x5a4d and ($dll and $save and (1 of ($c*)))
}