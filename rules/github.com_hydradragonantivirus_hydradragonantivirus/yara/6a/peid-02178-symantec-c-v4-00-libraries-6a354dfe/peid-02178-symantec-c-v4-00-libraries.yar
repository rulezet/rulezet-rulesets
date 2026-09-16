rule PEiD_02178_Symantec_C_v4_00___Libraries_ {
  meta:
    description = "[Symantec C v4.00 + Libraries]"
    ep_only     = "true"

  strings:
    $a = { FA B8 ?? ?? DB E3 8E D8 8C 06 ?? ?? 8B D8 2B 1E ?? ?? 89 1E ?? ?? 26 }

  condition:
    $a
}