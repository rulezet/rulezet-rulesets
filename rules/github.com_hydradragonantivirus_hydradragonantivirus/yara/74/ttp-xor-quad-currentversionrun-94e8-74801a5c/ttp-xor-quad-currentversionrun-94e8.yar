rule TTP_XOR_QUAD_CurrentVersionRun_94e8 {
  strings:
    $key_94e8 = { c7 87 [2] e3 89 [2] c8 a5 [2] e6 87 [2] f2 9c [2] fd 86 [2] e3 9b [2] e1 9a [2] fa 9c [2] e6 9b [2] fa b4 }

  condition:
    any of them
}