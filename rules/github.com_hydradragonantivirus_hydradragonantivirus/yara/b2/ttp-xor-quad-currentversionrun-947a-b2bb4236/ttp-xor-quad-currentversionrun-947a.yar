rule TTP_XOR_QUAD_CurrentVersionRun_947a {
  strings:
    $key_947a = { c7 15 [2] e3 1b [2] c8 37 [2] e6 15 [2] f2 0e [2] fd 14 [2] e3 09 [2] e1 08 [2] fa 0e [2] e6 09 [2] fa 26 }

  condition:
    any of them
}