rule Trojan_Hooker_Win32_Floxif_A_16 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09b11977f59db70beaeead2afe070b7e225f63ea5c7784210800c811bfac8330"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"XP style manifest\" proces" ascii
    $s2  = "mError: Could not get new comments. Your ID or password is incorrect; please re-enter your sign-in for access." fullword wide
    $s3  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"XP style manifest\" proces" ascii
    $s4  = "OError: Could not get new comments. One or more files are missing on the server." fullword wide
    $s5  = "E:\\Program Files (x86)\\Microsoft Visual Studio 10.0\\VC\\atlmfc\\include\\afxwin1.inl" fullword wide
    $s6  = "HKEY_CURRENT_USER\\Software\\Foxit Software\\Foxit Reader 9.0" fullword wide
    $s7  = "hitecture=\"x86\" version=\"1.0.0.0\" type=\"win32\"></assemblyIdentity><dependency><dependentAssembly><assemblyIdentity type=\"" ascii
    $s8  = "Empty CHeaderCtrlEx object!!Failed to create subclass header!" fullword wide
    $s9  = "SOFTWARE\\Foxit Software\\Foxit Reader Plus 8.50\\Preferences\\Languages" fullword wide
    $s10 = "SOFTWARE\\Foxit Software\\Foxit Reader 9.0\\Preferences\\Languages" fullword wide
    $s11 = "Invalid array size" fullword ascii
    $s12 = "@about:blank" fullword wide
    $s13 = "&Create PDF from Tracker Details" fullword wide
    $s14 = "Email All Reviewers$Start New Review with Same Reviewers" fullword wide
    $s15 = " 2014-2018 Foxit Software Inc. All Rights Reserved." fullword wide
    $s16 = "s\">true</ms_windowsSettings:dpiAware></windowsSettings></application><compatibility xmlns=\"urn:schemas-microsoft-com:compatibi" ascii
    $s17 = "ity></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><ms_windowsSettings:dpiAware xmlns:ms_w" ascii
    $s18 = "e=\"*\"></assemblyIdentity></dependentAssembly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><req" ascii
    $s19 = "ReName" fullword ascii
    $s20 = "`(null)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}