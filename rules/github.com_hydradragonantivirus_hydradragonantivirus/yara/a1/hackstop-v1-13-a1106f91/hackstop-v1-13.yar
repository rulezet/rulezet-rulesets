import "pe"
rule HACKSTOP_v1_13 {
  strings:
    $a0 = { 52 B8 ?? ?? 1E CD 21 86 E0 3D ?? ?? 73 ?? CD 20 0E 1F B4 09 E8 ?? ?? 24 ?? EA }

  condition:
    $a0 at pe.entry_point
}