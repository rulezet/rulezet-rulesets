rule TTP_XOR_QUAD_CurrentVersionRun_8d67 {
  strings:
    $key_8d67 = { de 08 [2] fa 06 [2] d1 2a [2] ff 08 [2] eb 13 [2] e4 09 [2] fa 14 [2] f8 15 [2] e3 13 [2] ff 14 [2] e3 3b }

  condition:
    any of them
}