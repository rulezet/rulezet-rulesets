rule TTP_XOR_QUAD_CurrentVersionRun_940a {
  strings:
    $key_940a = { c7 65 [2] e3 6b [2] c8 47 [2] e6 65 [2] f2 7e [2] fd 64 [2] e3 79 [2] e1 78 [2] fa 7e [2] e6 79 [2] fa 56 }

  condition:
    any of them
}