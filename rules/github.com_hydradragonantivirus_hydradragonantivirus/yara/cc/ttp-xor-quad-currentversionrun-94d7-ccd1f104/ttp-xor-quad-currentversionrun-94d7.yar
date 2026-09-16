rule TTP_XOR_QUAD_CurrentVersionRun_94d7 {
  strings:
    $key_94d7 = { c7 b8 [2] e3 b6 [2] c8 9a [2] e6 b8 [2] f2 a3 [2] fd b9 [2] e3 a4 [2] e1 a5 [2] fa a3 [2] e6 a4 [2] fa 8b }

  condition:
    any of them
}