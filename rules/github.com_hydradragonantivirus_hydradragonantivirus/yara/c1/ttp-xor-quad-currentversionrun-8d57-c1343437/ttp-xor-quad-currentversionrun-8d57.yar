rule TTP_XOR_QUAD_CurrentVersionRun_8d57 {
  strings:
    $key_8d57 = { de 38 [2] fa 36 [2] d1 1a [2] ff 38 [2] eb 23 [2] e4 39 [2] fa 24 [2] f8 25 [2] e3 23 [2] ff 24 [2] e3 0b }

  condition:
    any of them
}