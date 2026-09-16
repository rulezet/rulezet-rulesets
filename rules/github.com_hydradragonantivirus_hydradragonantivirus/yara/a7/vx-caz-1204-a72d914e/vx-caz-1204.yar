import "pe"
rule Vx__Caz_1204 {
  strings:
    $a0 = { E8 ?? ?? 5E 83 EE 03 1E 06 B8 FF FF CD 2F 3C 10 }

  condition:
    $a0 at pe.entry_point
}