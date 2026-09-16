import "pe"
rule _PIRIT_v1_5 {
  strings:
    $a0 = { B4 4D CD 21 E8 ?? ?? FD E8 ?? ?? B4 51 CD 21 }

  condition:
    $a0 at pe.entry_point
}