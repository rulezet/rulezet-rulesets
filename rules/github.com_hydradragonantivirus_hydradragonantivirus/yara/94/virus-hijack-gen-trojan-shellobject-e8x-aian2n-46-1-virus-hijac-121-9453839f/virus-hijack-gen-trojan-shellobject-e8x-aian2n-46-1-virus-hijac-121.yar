rule _Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_46_1_Virus_Hijac_121 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_46_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_47_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_48_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_49_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_5_1.vir, VirusShareTrojanPWSStealer31365_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0874d3cf49540e6898c5541da5bdc06fb9a868e8dafff1d3cad197ae7eeb5d03"
    hash2       = "1ea09cf3e057d9c68a8045165739492698f14054f2e77253968e68f600f16443"
    hash3       = "2d3f1362810906bf0522a3d0f4ff1400adb57539169f1b32b9dee249e9feff77"
    hash4       = "c170f17069409eac894e594d540582ffcafc660722e28e0661ec445d9b90d05a"
    hash5       = "d25e4bd684d12f265da034e3cd271556d0432b5549075e7e4b3cd0bbd9bbef42"
    hash6       = "76b7e0265f5fd3d3fead08df85a41d4fac0ab5bd881f9c44dca6987e69c9b63c"

  strings:
    $s1  = "Array index out of range : %dVThe DecisionCube Capacity is low. Please deactivate dimensions or change the data set.QQuery could" wide
    $s2  = "row error'No active summaries have been defined. -Not enough room available to load a summary. +No available dimensions have bee" wide
    $s3  = "False*The bin type does not match the fieldtype.,String Data type not supported for summaries" fullword wide
    $s4  = "%Axis Maximum Value must be >= Minimum$Axis Logarithmic Base should be >= 2" fullword wide
    $s5  = "Show shortcut keys in tips" fullword ascii
    $s6  = "General array error.4Initial Value is not legal for this type of Grouping" fullword wide
    $s7  = "COUNTALLSOne or more fields of a type which cannot be tabulated were removed from the query.7The maximum allowed dimensions of %" wide
    $s8  = "Drag to create Separators" fullword ascii
    $s9  = "$Me&nu show recently used items first" fullword ascii
    $s10 = "(Checkmark toggles visibility)" fullword ascii
    $s11 = "Show &tips on toolbars" fullword ascii
    $s12 = "Apply &to all toolbars" fullword ascii
    $s13 = "Axis increment must be >= 0%Axis Minimum Value must be <= Maximum" fullword wide
    $s14 = "uTo add actions to your application simply drag and drop from either Categories or Actions onto an existing ActionBar." fullword ascii
    $s15 = "&Caption Options" fullword ascii
    $s16 = "&Apply caption options &to all toolbars" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}