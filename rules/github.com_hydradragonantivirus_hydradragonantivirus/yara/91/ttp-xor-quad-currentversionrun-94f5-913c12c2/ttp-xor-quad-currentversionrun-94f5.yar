rule TTP_XOR_QUAD_CurrentVersionRun_94f5 {
  strings:
    $key_94f5 = { c7 9a [2] e3 94 [2] c8 b8 [2] e6 9a [2] f2 81 [2] fd 9b [2] e3 86 [2] e1 87 [2] fa 81 [2] e6 86 [2] fa a9 }

  condition:
    any of them
}