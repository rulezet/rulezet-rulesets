rule TTP_XOR_QUAD_CurrentVersionRun_94d2 {
  strings:
    $key_94d2 = { c7 bd [2] e3 b3 [2] c8 9f [2] e6 bd [2] f2 a6 [2] fd bc [2] e3 a1 [2] e1 a0 [2] fa a6 [2] e6 a1 [2] fa 8e }

  condition:
    any of them
}