rule PEiD_03375_Vx__Danish_tiny_ {
  meta:
    description = "[Vx: Danish tiny]"
    ep_only     = "true"

  strings:
    $a = { 33 C9 B4 4E CD 21 73 02 FF ?? BA ?? 00 B8 ?? 3D CD 21 }

  condition:
    $a
}