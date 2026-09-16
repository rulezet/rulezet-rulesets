rule _Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_46_1_Virus_Hijac_65 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_46_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_47_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_48_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_49_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0874d3cf49540e6898c5541da5bdc06fb9a868e8dafff1d3cad197ae7eeb5d03"
    hash2       = "1ea09cf3e057d9c68a8045165739492698f14054f2e77253968e68f600f16443"
    hash3       = "2d3f1362810906bf0522a3d0f4ff1400adb57539169f1b32b9dee249e9feff77"
    hash4       = "c170f17069409eac894e594d540582ffcafc660722e28e0661ec445d9b90d05a"
    hash5       = "d25e4bd684d12f265da034e3cd271556d0432b5549075e7e4b3cd0bbd9bbef42"

  strings:
    $s1  = "0Cannot perform this operation on an open dataset\"Dataset not in edit or insert mode1Cannot perform this operation on a closed " wide
    $s2  = "No help keyword specified.$Error creating system registry entry" fullword wide
    $s3  = " - Dock zone has no controleCannot assign a subitem to an actionbar when one of it's parent's is already assigned to an actionba" wide
    $s4  = "8Listbox (%s) style must be virtual in order to set Count" fullword wide
    $s5  = "/No argument provided for an operator or summary1An expression cannot be used for a grouping field" fullword wide
    $s6  = "Not Available[Information required to do Maximum Cell limit is not current.  Do you want to fetch it now?4Date grouping is not a" wide
    $s7  = "Invalid SQL date/time valuesZCannot enable AutoSessionName property with more than one session on a form or data-module^Cannot a" wide
    $s8  = "Reset ToolbarCircular references not allowed" fullword wide
    $s9  = "Color LH" fullword ascii
    $s10 = "TAction`/F" fullword ascii
    $s11 = "Background@FH" fullword ascii
    $s12 = "Alignment`aF" fullword ascii
    $s13 = "Stated?H" fullword ascii
    $s14 = "0009/Top Legend Position must be between 0 and 100 %" fullword wide
    $s15 = "Other Values" fullword wide
    $s16 = "$Incorrectly formed filter expression" fullword wide
    $s17 = "Constant out of range" fullword wide
    $s18 = "5Cannot build the Decision Cube with an empty data set!Data set property is not assigned" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}