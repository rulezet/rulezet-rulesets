rule TTP_XOR_QUAD_CurrentVersionRun_8d18 {
  strings:
    $key_8d18 = { de 77 [2] fa 79 [2] d1 55 [2] ff 77 [2] eb 6c [2] e4 76 [2] fa 6b [2] f8 6a [2] e3 6c [2] ff 6b [2] e3 44 }

  condition:
    any of them
}