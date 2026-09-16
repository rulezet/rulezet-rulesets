rule TTP_XOR_QUAD_CurrentVersionRun_94fa {
  strings:
    $key_94fa = { c7 95 [2] e3 9b [2] c8 b7 [2] e6 95 [2] f2 8e [2] fd 94 [2] e3 89 [2] e1 88 [2] fa 8e [2] e6 89 [2] fa a6 }

  condition:
    any of them
}