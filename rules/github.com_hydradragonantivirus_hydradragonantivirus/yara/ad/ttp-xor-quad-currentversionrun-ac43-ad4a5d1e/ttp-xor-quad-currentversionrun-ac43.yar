rule TTP_XOR_QUAD_CurrentVersionRun_ac43 {
  strings:
    $key_ac43 = { ff 2c [2] db 22 [2] f0 0e [2] de 2c [2] ca 37 [2] c5 2d [2] db 30 [2] d9 31 [2] c2 37 [2] de 30 [2] c2 1f }

  condition:
    any of them
}