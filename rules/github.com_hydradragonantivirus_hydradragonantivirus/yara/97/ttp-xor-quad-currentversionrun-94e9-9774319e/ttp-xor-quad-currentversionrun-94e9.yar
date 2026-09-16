rule TTP_XOR_QUAD_CurrentVersionRun_94e9 {
  strings:
    $key_94e9 = { c7 86 [2] e3 88 [2] c8 a4 [2] e6 86 [2] f2 9d [2] fd 87 [2] e3 9a [2] e1 9b [2] fa 9d [2] e6 9a [2] fa b5 }

  condition:
    any of them
}