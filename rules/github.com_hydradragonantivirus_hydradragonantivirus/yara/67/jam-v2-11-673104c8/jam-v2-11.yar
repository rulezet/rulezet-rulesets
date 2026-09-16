import "pe"
rule JAM_v2_11 {
  strings:
    $a0 = { 50 06 16 07 BE ?? ?? 8B FE B9 ?? ?? FD FA F3 2E A5 FB 06 BD ?? ?? 55 CB }

  condition:
    $a0 at pe.entry_point
}