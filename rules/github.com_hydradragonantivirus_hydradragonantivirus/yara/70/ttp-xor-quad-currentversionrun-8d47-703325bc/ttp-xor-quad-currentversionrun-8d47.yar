rule TTP_XOR_QUAD_CurrentVersionRun_8d47 {
  strings:
    $key_8d47 = { de 28 [2] fa 26 [2] d1 0a [2] ff 28 [2] eb 33 [2] e4 29 [2] fa 34 [2] f8 35 [2] e3 33 [2] ff 34 [2] e3 1b }

  condition:
    any of them
}