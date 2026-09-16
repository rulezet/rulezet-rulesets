import "pe"
rule Vx__Involuntary_1349 {
  strings:
    $a0 = { BA ?? ?? B9 ?? ?? 8C DD ?? 8C C8 ?? 8E D8 8E C0 33 F6 8B FE FC ?? ?? AD ?? 33 C2 AB }

  condition:
    $a0 at pe.entry_point
}