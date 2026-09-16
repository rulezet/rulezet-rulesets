import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_9_2_Virus_Hijac_225 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_15.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94ba8ada91c588b0d34ace935bd348f16710a42ed15afe901c5907e75f21c669"
    hash2       = "73aa59479f9458ba652e50e7d468cd3aba6acc68aa59271105fd4dad61f63e4f"
    hash3       = "27904883eadd9fe5de0efa575a0268b49b353c42033ebdd27b97b7b639e28bdc"

  strings:
    $s1  = "Scan script" fullword ascii
    $s2  = "not supported with nonstan" fullword ascii
    $s3  = "The procedure %s co" fullword ascii
    $s4  = "number %d.%02" fullword ascii
    $s5  = "multiple use" fullword ascii
    $s6  = "{tart Of Scan:" fullword ascii
    $s7  = "?eous bytes before" fullword ascii
    $s8  = "very acU&" fullword ascii
    $s9  = ", assuming YCbCr" fullword ascii
    $s10 = "Pdisk space" fullword ascii
    $s11 = "legal restri9sG`Sy?a" fullword ascii
    $s12 = "'Obtained XMS handle %u" fullword ascii
    $s13 = "Inconsistent progres" fullword ascii
    $s14 = "Warning: unknown JFIF " fullword ascii
    $s15 = "Invalid SOS parameters" fullword ascii
    $s16 = ";+%`dynamic " fullword ascii
    $s17 = "Premature en" fullword ascii
    $s18 = "most like-" fullword ascii
    $s19 = "Virtual array co" fullword ascii
    $s20 = ": RGB thumbnail " fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "09d0478591d4f788cb3e5ea416c25237" and (8 of them)
    ) or (all of them)
}