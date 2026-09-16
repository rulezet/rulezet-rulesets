rule PEiD_02260_Thinstall_Embedded_V2_545____Jitit___Sign_by_fly_ {
  meta:
    description = "[Thinstall Embedded V2.545 -> Jitit ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { E8 F2 FF FF FF 50 68 ?? ?? ?? ?? 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00 }

  condition:
    $a
}