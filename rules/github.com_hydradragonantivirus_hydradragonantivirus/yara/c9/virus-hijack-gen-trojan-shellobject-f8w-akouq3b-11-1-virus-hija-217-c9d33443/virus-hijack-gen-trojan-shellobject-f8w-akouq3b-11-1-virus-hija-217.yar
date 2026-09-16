import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_11_1_Virus_Hija_217 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash2       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"

  strings:
    $x1  = "<!DOCTYPE Sysmon [<!ELEMENT Sysmon (EventFiltering|ArchiveDirectory|CaptureClipboard|DriverName|PipeMonitoringConfig|HashAlgorit" wide
    $s2  = "\\caps\\fs20 6.\\tab\\fs19 Export Restrictions\\caps0 .\\b0   The software is subject to United States export laws and regulatio" ascii
    $s3  = "/PRODUCT:Reader /VERSION:21.0 /MODE:" fullword wide
    $s4  = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab anything related to the software, services, content (including code) on thi" ascii
    $s5  = "The software is subject to United States export laws and regulations.You must comply with all domestic and international export " wide
    $s6  = "/ArmPrefs /PRODUCT:Reader" fullword wide
    $s7  = "\\'b7\\tab support" fullword ascii
    $s8  = "ficier de droits additionnels en vertu du droit local sur la protection dues consommateurs, que ce contrat ne peut modifier. La " wide
    $s9  = ", version, requestUrl FROM Property" fullword wide
    $s10 = "United States.If you acquired the software in the United States, Washington state law governs the interpretation of this agreeme" wide
    $s11 = "I\\Google\\Chrome\\User Data\\Local State" fullword wide
    $s12 = "\\pard\\fi-357\\li357\\sb120\\sa120\\tx360\\b\\fs20 3.\\tab SENSITIVE INFORMATION. \\b0  Pl" fullword ascii
    $s13 = "ation, you may use the software only as expressly" fullword ascii
    $s14 = "|iCCPICC Profile" fullword ascii
    $s15 = "<path fill=\"#010101\" d=\"M24,26c-0.109-2.5-1.1" fullword ascii
    $s16 = "United States.If you acquired the software in the United States, Washington state law governs the interpretation of this agreeme" wide
    $s17 = "([[:alnum:]]+[_][[:digit:].]+[_][[:alnum:]]+[_][[:alnum:]]+[_][[:xdigit:]]{8}[-][[:xdigit:]]{4}[-][[:xdigit:]]{4}[-][[:xdigit:]]" wide
    $s18 = "([[:digit:]]+[_][[:digit:]]+)?" fullword wide
    $s19 = "escape filter eleme" fullword wide
    $s20 = "o not permit it to do so.\\b\\cap" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "539502771da573641ecc7f6497e39f8f" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}