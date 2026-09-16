rule TTP_XOR_QUAD_CurrentVersionRun_941d {
  strings:
    $key_941d = { c7 72 [2] e3 7c [2] c8 50 [2] e6 72 [2] f2 69 [2] fd 73 [2] e3 6e [2] e1 6f [2] fa 69 [2] e6 6e [2] fa 41 }

  condition:
    any of them
}