rule TTP_XOR_QUAD_CurrentVersionRun_944d {
  strings:
    $key_944d = { c7 22 [2] e3 2c [2] c8 00 [2] e6 22 [2] f2 39 [2] fd 23 [2] e3 3e [2] e1 3f [2] fa 39 [2] e6 3e [2] fa 11 }

  condition:
    any of them
}