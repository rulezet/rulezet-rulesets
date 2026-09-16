rule Virus_Hijack_GenPack_Backdoor_Hangup_B_46_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_46_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef441397450e9bc6910c9574c659f1f2ad04d74b1490f767bdad003f1d0e9fec"

  strings:
    $x1  = "<!-- Localization note (safeb.blocked.malware.shortDesc) - Please don't translate the contents of the <span id=\"malware_sitenam" ascii
    $x2  = "<!-- Localization note (safeb.blocked.phishing.shortDesc) - Please don't translate the contents of the <span id=\"phishing_siten" ascii
    $x3  = "<!ENTITY fullZoomEnlargeCmd.commandkey2 \"=\"> <!-- + is above this key on many keyboards -->" fullword ascii
    $s4  = "The file to be verified is C:\\WINDOWS\\system32\\prntvpt.dll." fullword ascii
    $s5  = "The file to be verified is C:\\WINDOWS\\system32\\windowscodecs.dll." fullword ascii
    $s6  = "The file to be verified is C:\\WINDOWS\\system32\\msi.dll." fullword ascii
    $s7  = "The file to be verified is C:\\WINDOWS\\system32\\rgb9rast_2.dll." fullword ascii
    $s8  = "The file to be verified is C:\\WINDOWS\\system32\\msxml6.dll." fullword ascii
    $s9  = "<xul:button xmlns:xul='http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul' id='exceptionDialogButton' label='&securit" ascii
    $s10 = "CertDumpExtensionFailure=Error: Unable to process extension" fullword ascii
    $s11 = "<xul:button xmlns:xul='http://www.mozilla.org/keymaster/gatekeeper/there.is.only.xul' id='getMeOutOfHereButton' label='&security" ascii
    $s12 = "<!-- Command Bar items -->" fullword ascii
    $s13 = "\"/> tag.  It will be replaced at runtime with a domain name (e.g. www.badsite.com) -->" fullword ascii
    $s14 = "<!ENTITY reportForm.behind_login.title              \"Web site is password-protected\"><!-- No \":\" at the end -->" fullword ascii
    $s15 = "  // Otherwise, dump to stdout and launch an assertion failure dialog" fullword ascii
    $s16 = "me\"/> tag. It will be replaced at runtime with a domain name (e.g. www.badsite.com) -->" fullword ascii
    $s17 = "locale/en-US/mozapps/downloads/unknownContentType.dtd<!-- -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4" ascii
    $s18 = "<!-- Strings for the SSL client auth ask dialog -->" fullword ascii
    $s19 = "<!ENTITY dnsNotFound.longDesc \"<p>The browser could not find the host server for the provided address.</p><ul><li>Did you make " ascii
    $s20 = "locale/en-US/mozapps/downloads/unknownContentType.dtd<!-- -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}