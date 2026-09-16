rule TTP_XOR_QUAD_CurrentVersionRun_94e4 {
  strings:
    $key_94e4 = { c7 8b [2] e3 85 [2] c8 a9 [2] e6 8b [2] f2 90 [2] fd 8a [2] e3 97 [2] e1 96 [2] fa 90 [2] e6 97 [2] fa b8 }

  condition:
    any of them
}