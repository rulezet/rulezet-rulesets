rule TTP_XOR_QUAD_CurrentVersionRun_94d5 {
  strings:
    $key_94d5 = { c7 ba [2] e3 b4 [2] c8 98 [2] e6 ba [2] f2 a1 [2] fd bb [2] e3 a6 [2] e1 a7 [2] fa a1 [2] e6 a6 [2] fa 89 }

  condition:
    any of them
}