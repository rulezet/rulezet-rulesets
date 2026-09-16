rule TTP_XOR_QUAD_CurrentVersionRun_941c {
  strings:
    $key_941c = { c7 73 [2] e3 7d [2] c8 51 [2] e6 73 [2] f2 68 [2] fd 72 [2] e3 6f [2] e1 6e [2] fa 68 [2] e6 6f [2] fa 40 }

  condition:
    any of them
}