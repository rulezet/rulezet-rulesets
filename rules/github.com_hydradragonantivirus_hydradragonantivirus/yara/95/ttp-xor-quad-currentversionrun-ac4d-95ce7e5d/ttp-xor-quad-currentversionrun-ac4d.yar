rule TTP_XOR_QUAD_CurrentVersionRun_ac4d {
  strings:
    $key_ac4d = { ff 22 [2] db 2c [2] f0 00 [2] de 22 [2] ca 39 [2] c5 23 [2] db 3e [2] d9 3f [2] c2 39 [2] de 3e [2] c2 11 }

  condition:
    any of them
}