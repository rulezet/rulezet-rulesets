rule TTP_XOR_QUAD_CurrentVersionRun_ac46 {
  strings:
    $key_ac46 = { ff 29 [2] db 27 [2] f0 0b [2] de 29 [2] ca 32 [2] c5 28 [2] db 35 [2] d9 34 [2] c2 32 [2] de 35 [2] c2 1a }

  condition:
    any of them
}