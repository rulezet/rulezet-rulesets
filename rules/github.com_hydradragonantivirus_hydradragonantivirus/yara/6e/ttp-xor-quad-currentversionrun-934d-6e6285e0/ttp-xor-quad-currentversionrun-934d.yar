rule TTP_XOR_QUAD_CurrentVersionRun_934d {
  strings:
    $key_934d = { c0 22 [2] e4 2c [2] cf 00 [2] e1 22 [2] f5 39 [2] fa 23 [2] e4 3e [2] e6 3f [2] fd 39 [2] e1 3e [2] fd 11 }

  condition:
    any of them
}