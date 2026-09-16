rule PEiD_00870_HACKSTOP_v1_11c_ {
  meta:
    description = "[HACKSTOP v1.11c]"
    ep_only     = "true"

  strings:
    $a = { B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 ?? CD 21 B0 ?? B4 4C CD 21 53 BB ?? ?? 5B EB }

  condition:
    $a
}