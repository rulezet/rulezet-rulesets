rule TTP_XOR_QUAD_CurrentVersionRun_ac52 {
  strings:
    $key_ac52 = { ff 3d [2] db 33 [2] f0 1f [2] de 3d [2] ca 26 [2] c5 3c [2] db 21 [2] d9 20 [2] c2 26 [2] de 21 [2] c2 0e }

  condition:
    any of them
}