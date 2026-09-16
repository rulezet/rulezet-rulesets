rule Trojan_Sysbot_Application_Downloader {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Application.Downloader.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84289d1c64834674edc7faa530ed3cb6c57b0329f37658d9e9cad23512c216bb"

  strings:
    $x1  = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2  = "ndency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"hig" ascii
    $s3  = "CreateThread Error" fullword wide
    $s4  = "Dialog Error" fullword wide
    $s5  = "Transfer Error" fullword wide
    $s6  = "Reget Error" fullword wide
    $s7  = "OpenRequest Error" fullword wide
    $s8  = "SendRequest Error" fullword wide
    $s9  = "URL Parts Error" fullword wide
    $s10 = "Request Error" fullword wide
    $s11 = "Error FTP path (550)" fullword wide
    $s12 = "tAvailable\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:c" ascii
    $s13 = "Proxy-authorization: basic %s" fullword wide
    $s14 = "Are you sure that you want to stop download?" fullword wide
    $s15 = "File Read Error" fullword wide
    $s16 = "Reconnect Pause" fullword wide
    $s17 = "Your internet connection seems to be not permitted or dropped out!" fullword wide
    $s18 = "Authorization: basic %s" fullword wide
    $s19 = "Open Internet Error" fullword wide
    $s20 = "Open URL Error" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}