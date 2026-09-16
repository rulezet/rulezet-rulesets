rule TTP_XOR_QUAD_CurrentVersionRun_8d55 {
  strings:
    $key_8d55 = { de 3a [2] fa 34 [2] d1 18 [2] ff 3a [2] eb 21 [2] e4 3b [2] fa 26 [2] f8 27 [2] e3 21 [2] ff 26 [2] e3 09 }

  condition:
    any of them
}