rule TTP_XOR_QUAD_CurrentVersionRun_8d25 {
  strings:
    $key_8d25 = { de 4a [2] fa 44 [2] d1 68 [2] ff 4a [2] eb 51 [2] e4 4b [2] fa 56 [2] f8 57 [2] e3 51 [2] ff 56 [2] e3 79 }

  condition:
    any of them
}