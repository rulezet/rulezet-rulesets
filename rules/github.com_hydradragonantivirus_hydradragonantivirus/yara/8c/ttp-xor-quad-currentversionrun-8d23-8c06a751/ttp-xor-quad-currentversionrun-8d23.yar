rule TTP_XOR_QUAD_CurrentVersionRun_8d23 {
  strings:
    $key_8d23 = { de 4c [2] fa 42 [2] d1 6e [2] ff 4c [2] eb 57 [2] e4 4d [2] fa 50 [2] f8 51 [2] e3 57 [2] ff 50 [2] e3 7f }

  condition:
    any of them
}