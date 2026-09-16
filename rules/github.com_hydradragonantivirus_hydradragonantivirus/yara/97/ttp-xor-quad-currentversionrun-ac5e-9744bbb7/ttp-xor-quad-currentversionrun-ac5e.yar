rule TTP_XOR_QUAD_CurrentVersionRun_ac5e {
  strings:
    $key_ac5e = { ff 31 [2] db 3f [2] f0 13 [2] de 31 [2] ca 2a [2] c5 30 [2] db 2d [2] d9 2c [2] c2 2a [2] de 2d [2] c2 02 }

  condition:
    any of them
}