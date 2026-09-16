rule TTP_XOR_QUAD_CurrentVersionRun_8d75 {
  strings:
    $key_8d75 = { de 1a [2] fa 14 [2] d1 38 [2] ff 1a [2] eb 01 [2] e4 1b [2] fa 06 [2] f8 07 [2] e3 01 [2] ff 06 [2] e3 29 }

  condition:
    any of them
}