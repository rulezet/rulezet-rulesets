rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCeX4wn_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCeX4wn_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cd675efb7bb4dd6bfd36bf1451cc4d7f6bee40cdd35e0b9d7ac985552ecca07"

  strings:
    $s1  = "2020-06-08 10:28:12, Info                  CBS    Loaded Servicing Stack v6.1.7601.17514 with Core: C:\\Windows\\winsxs\\amd64_m" ascii
    $s2  = "dispci.dll:  DispCIIsDeviceCompatibleWithHighResolutionBoot: Found high resolution boot incomaptible hardware DispCIIsDeviceComp" ascii
    $s3  = "dispci.dll:  DispCIIsDeviceCompatibleWithHighResolutionBoot: Found high resolution boot incomaptible hardware DispCIIsDeviceComp" ascii
    $s4  = "dispci.dll:  DispCISetServiceStartType: No change to the service start required" fullword ascii
    $s5  = "dispci.dll:  DispCIIsDriverInstallAllowed: Driver package contains a feature score 0xfe" fullword ascii
    $s6  = "2020-06-08 10:28:17, Info                  CBS    SQM: Failed to start upload with file pattern: C:\\Windows\\servicing\\sqm\\*_" ascii
    $s7  = "2020-06-08 10:28:17, Info                  CBS    SQM: Failed to start upload with file pattern: C:\\Windows\\servicing\\sqm\\*_" ascii
    $s8  = "montr_ci.dll:  Retrieving driver details...." fullword ascii
    $s9  = "montr_ci.dll:  Returning 0xe000020e for function 0xc." fullword ascii
    $s10 = "montr_ci.dll:  Returning 0xe000020e for function 0x15 and device DISPLAY\\DEFAULT_MONITOR\\5&2DCF5EAB&0&12345678&06&05." fullword ascii
    $s11 = "montr_ci.dll:  Returning 0xe000020e for function 0x17 and device DISPLAY\\DEFAULT_MONITOR\\5&2FAB8E39&0&12345678&06&05." fullword ascii
    $s12 = "montr_ci.dll:  Returning 0xe000020e for function 0x1e and device DISPLAY\\DEFAULT_MONITOR\\4&2ABFAA30&0&12345678&00&02." fullword ascii
    $s13 = "montr_ci.dll:  Returning 0xe000020e for function 0xc and device DISPLAY\\DEFAULT_MONITOR\\5&2DCF5EAB&0&12345678&06&05." fullword ascii
    $s14 = "montr_ci.dll:  Returning 0xe000020e for function 0x18 and device DISPLAY\\DEFAULT_MONITOR\\5&2FAB8E39&0&12345678&06&05." fullword ascii
    $s15 = "montr_ci.dll:  Returning 0xe000020e for function 0x1e and device DISPLAY\\DEFAULT_MONITOR\\5&2FAB8E39&0&12345678&06&05." fullword ascii
    $s16 = "montr_ci.dll:  Returning 0xe000020e for function 0x18 and device DISPLAY\\DEFAULT_MONITOR\\4&2ABFAA30&0&12345678&00&02." fullword ascii
    $s17 = "montr_ci.dll:  Returning 0xe000020e for function 0x18 and device DISPLAY\\DEFAULT_MONITOR\\5&2DCF5EAB&0&12345678&06&05." fullword ascii
    $s18 = "montr_ci.dll:  Returning 0xe000020e for function 0x17 and device DISPLAY\\DEFAULT_MONITOR\\4&2ABFAA30&0&12345678&00&02." fullword ascii
    $s19 = "montr_ci.dll:  Returning 0xe000020e for function 0x15 and device DISPLAY\\DEFAULT_MONITOR\\4&2ABFAA30&0&12345678&00&02." fullword ascii
    $s20 = "montr_ci.dll:  Returning 0xe000020e for function 0x6." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}