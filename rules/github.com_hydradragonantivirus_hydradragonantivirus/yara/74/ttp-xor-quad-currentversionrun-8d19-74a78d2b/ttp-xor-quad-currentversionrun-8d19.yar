rule TTP_XOR_QUAD_CurrentVersionRun_8d19 {
  strings:
    $key_8d19 = { de 76 [2] fa 78 [2] d1 54 [2] ff 76 [2] eb 6d [2] e4 77 [2] fa 6a [2] f8 6b [2] e3 6d [2] ff 6a [2] e3 45 }

  condition:
    any of them
}