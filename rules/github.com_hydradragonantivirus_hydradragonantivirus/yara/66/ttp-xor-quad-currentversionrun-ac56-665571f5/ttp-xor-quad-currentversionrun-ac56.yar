rule TTP_XOR_QUAD_CurrentVersionRun_ac56 {
  strings:
    $key_ac56 = { ff 39 [2] db 37 [2] f0 1b [2] de 39 [2] ca 22 [2] c5 38 [2] db 25 [2] d9 24 [2] c2 22 [2] de 25 [2] c2 0a }

  condition:
    any of them
}