rule TTP_XOR_QUAD_CurrentVersionRun_ac4e {
  strings:
    $key_ac4e = { ff 21 [2] db 2f [2] f0 03 [2] de 21 [2] ca 3a [2] c5 20 [2] db 3d [2] d9 3c [2] c2 3a [2] de 3d [2] c2 12 }

  condition:
    any of them
}