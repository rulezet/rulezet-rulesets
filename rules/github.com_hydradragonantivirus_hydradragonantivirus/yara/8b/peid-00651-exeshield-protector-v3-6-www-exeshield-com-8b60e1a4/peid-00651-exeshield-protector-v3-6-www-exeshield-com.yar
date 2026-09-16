rule PEiD_00651_ExeShield_Protector_V3_6____www_exeshield_com_ {
  meta:
    description = "[ExeShield Protector V3.6 -> www.exeshield.com]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? ?? 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC }

  condition:
    $a
}