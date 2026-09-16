rule TTP_XOR_QUAD_CurrentVersionRun_8d1b {
  strings:
    $key_8d1b = { de 74 [2] fa 7a [2] d1 56 [2] ff 74 [2] eb 6f [2] e4 75 [2] fa 68 [2] f8 69 [2] e3 6f [2] ff 68 [2] e3 47 }

  condition:
    any of them
}