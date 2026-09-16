import "pe"
rule Vx__Trivial_46 {
  strings:
    $a0 = { B4 4E B1 20 BA ?? ?? CD 21 BA ?? ?? B8 ?? 3D CD 21 }

  condition:
    $a0 at pe.entry_point
}