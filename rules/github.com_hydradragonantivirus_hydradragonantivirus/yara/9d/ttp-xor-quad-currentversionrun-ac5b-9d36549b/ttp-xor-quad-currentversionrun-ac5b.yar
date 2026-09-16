rule TTP_XOR_QUAD_CurrentVersionRun_ac5b {
  strings:
    $key_ac5b = { ff 34 [2] db 3a [2] f0 16 [2] de 34 [2] ca 2f [2] c5 35 [2] db 28 [2] d9 29 [2] c2 2f [2] de 28 [2] c2 07 }

  condition:
    any of them
}