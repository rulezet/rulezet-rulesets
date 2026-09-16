rule TTP_XOR_QUAD_CurrentVersionRun_8d04 {
  strings:
    $key_8d04 = { de 6b [2] fa 65 [2] d1 49 [2] ff 6b [2] eb 70 [2] e4 6a [2] fa 77 [2] f8 76 [2] e3 70 [2] ff 77 [2] e3 58 }

  condition:
    any of them
}