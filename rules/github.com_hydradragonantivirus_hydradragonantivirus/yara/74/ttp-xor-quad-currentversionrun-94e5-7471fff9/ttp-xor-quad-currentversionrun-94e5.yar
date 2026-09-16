rule TTP_XOR_QUAD_CurrentVersionRun_94e5 {
  strings:
    $key_94e5 = { c7 8a [2] e3 84 [2] c8 a8 [2] e6 8a [2] f2 91 [2] fd 8b [2] e3 96 [2] e1 97 [2] fa 91 [2] e6 96 [2] fa b9 }

  condition:
    any of them
}