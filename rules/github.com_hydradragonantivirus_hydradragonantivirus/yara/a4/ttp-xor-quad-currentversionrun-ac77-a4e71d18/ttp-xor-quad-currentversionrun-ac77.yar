rule TTP_XOR_QUAD_CurrentVersionRun_ac77 {
  strings:
    $key_ac77 = { ff 18 [2] db 16 [2] f0 3a [2] de 18 [2] ca 03 [2] c5 19 [2] db 04 [2] d9 05 [2] c2 03 [2] de 04 [2] c2 2b }

  condition:
    any of them
}