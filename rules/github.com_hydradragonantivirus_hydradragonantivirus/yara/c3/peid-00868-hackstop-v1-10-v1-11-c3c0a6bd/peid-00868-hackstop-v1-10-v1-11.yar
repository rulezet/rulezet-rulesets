rule PEiD_00868_HACKSTOP_v1_10__v1_11_ {
  meta:
    description = "[HACKSTOP v1.10, v1.11]"
    ep_only     = "true"

  strings:
    $a = { B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 2F CD 21 B0 ?? B4 4C CD 21 50 B8 ?? ?? 58 EB }

  condition:
    $a
}