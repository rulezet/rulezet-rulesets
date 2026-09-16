rule TTP_XOR_QUAD_CurrentVersionRun_8d5f {
  strings:
    $key_8d5f = { de 30 [2] fa 3e [2] d1 12 [2] ff 30 [2] eb 2b [2] e4 31 [2] fa 2c [2] f8 2d [2] e3 2b [2] ff 2c [2] e3 03 }

  condition:
    any of them
}