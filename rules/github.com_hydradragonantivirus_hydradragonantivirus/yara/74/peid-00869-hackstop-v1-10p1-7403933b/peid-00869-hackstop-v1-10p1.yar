rule PEiD_00869_HACKSTOP_v1_10p1_ {
  meta:
    description = "[HACKSTOP v1.10p1]"
    ep_only     = "true"

  strings:
    $a = { B4 30 CD 21 86 E0 3D 00 03 73 ?? B4 2F CD 21 B4 2A CD 21 B4 2C CD 21 B0 FF B4 4C CD 21 50 B8 ?? ?? 58 EB }

  condition:
    $a
}