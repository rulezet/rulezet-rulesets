rule PEiD_00801_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_Basic___MASM32__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual Basic / MASM32)]"
    ep_only     = "true"

  strings:
    $a = { EB 02 09 94 0F B7 FF 68 80 ?? ?? 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }

  condition:
    $a
}