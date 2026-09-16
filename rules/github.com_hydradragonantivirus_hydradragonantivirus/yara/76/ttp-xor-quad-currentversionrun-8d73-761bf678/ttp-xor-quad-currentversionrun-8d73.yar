rule TTP_XOR_QUAD_CurrentVersionRun_8d73 {
  strings:
    $key_8d73 = { de 1c [2] fa 12 [2] d1 3e [2] ff 1c [2] eb 07 [2] e4 1d [2] fa 00 [2] f8 01 [2] e3 07 [2] ff 00 [2] e3 2f }

  condition:
    any of them
}