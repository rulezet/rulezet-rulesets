import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_65_1_Virus_Hijac_175 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_65_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_8_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCXl7mh_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCXl7mh_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59765b3d2b64984f23529acdf9def9178bac528428335f662e5bac2d1012175e"
    hash2       = "c552bb64871b29a9ff3c1472e6bf04f5b05e5f592f9b20deb8e9bdf51f2bdf1a"
    hash3       = "8a68047f167c1aec5af6010ae4a5cca64d815b4b92ce99ac94a7e25bb7269359"
    hash4       = "95bd66419f1bf28c5b02aca34fd1719ebca3405349e1751c09ea6af91870f5b5"

  strings:
    $s1  = "&Avast Command-line Scanner, version %s)(c) Copyright 1988 - 2016, AVAST Software !! Following task is not known: $!! Scan was i" wide
    $s2  = "Archive is password protected.+Compressed file is too big to be processed.?Not enough disk space in TEMP directory to uncompress" wide
    $s3  = "5Cannot load aswUInt.dll (main user interface module).3Cannot load Lang.dll from selected language folder.CThere was a problem w" wide
    $s4  = "<Virus scanning is off>)Found virus %s, testing is interrupted!!!" fullword wide
    $s5  = "Operating memory:Process %u [%s], memory block 0x%016I64X, block size %I64u" fullword wide
    $s6  = "&Scan %skAvast UI process (AvastUI.exe) is currently not running." fullword wide
    $s7  = "=[JZIMXRSTGCBWOEQHFVKPY7D6U4123AN]  J:ARJ, Z:ZIP, I:MIME, M:MAPI, X:DosExec, R:RAR, S:Streams, T:TAR, G:GZ, C:CAB, B:BZIP2, W:Wi" wide
    $s8  = "<area name>6\"C:\\Program files\" /p /t=ZJIX --soundoff /v=\"key kapt\"CPaging the lines if program is not in STDOUT mode ( para" wide
    $s9  = "It is probably a boot virus, already activated!!!QInfected files: %I64d" fullword wide
    $s10 = "Press any key to continue.2The Avast Command-line Scanner has been aborted...*Help. Short description of all parameters." fullword wide
    $s11 = "Program doesn't wait for user input (/p). Automatic action with infected file: /p=[01234] 0:fix automatically, 1:delete file, 2:" wide
    $s12 = ")Attempt to load kernel driver %s blocked." fullword wide
    $s13 = "6System library COMCTL32.DLL is old and cannot be used.3System library MFC70.DLL is old and cannot be used." fullword wide
    $s14 = "<Network Shield: blocked \"%s\" - attack from %d.%d.%d.%d:%d/%s3Network Shield: blocked access to malicious site %s" fullword wide
    $s15 = "Virus infects documents.7Virus infects executables and system parts of the disk.'Virus infects system parts of the disk.$Virus c" wide
    $s16 = "Internal program error./Cannot create folder, some file already exists.'Error occurred during data compression.0File is offline " wide
    $s17 = "Shred the selected items...nAvast UI process (AvastUI.exe) is currently not running." fullword wide
    $s18 = "Program cannot get storage!'Scan was completed with error." fullword wide
    $s19 = "* Avast Scan Report" fullword wide
    $s20 = "* Avast Real-time Shield Scan Report" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "a9192bab5c7c795c7488b69a1853f9c2" and (8 of them)
    ) or (all of them)
}