import "pe"
rule Vx__Modification_of_Hi_924 {
  strings:
    $a0 = { 50 53 51 52 1E 06 9C B8 21 35 CD 21 53 BB ?? ?? 26 ?? ?? 49 48 5B }

  condition:
    $a0 at pe.entry_point
}