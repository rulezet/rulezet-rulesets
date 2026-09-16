rule TTP_XOR_QUAD_CurrentVersionRun_ac2c {
  strings:
    $key_ac2c = { ff 43 [2] db 4d [2] f0 61 [2] de 43 [2] ca 58 [2] c5 42 [2] db 5f [2] d9 5e [2] c2 58 [2] de 5f [2] c2 70 }

  condition:
    any of them
}