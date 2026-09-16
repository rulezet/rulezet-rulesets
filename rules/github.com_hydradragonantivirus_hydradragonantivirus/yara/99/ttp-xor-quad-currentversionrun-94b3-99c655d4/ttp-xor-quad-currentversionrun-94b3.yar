rule TTP_XOR_QUAD_CurrentVersionRun_94b3 {
  strings:
    $key_94b3 = { c7 dc [2] e3 d2 [2] c8 fe [2] e6 dc [2] f2 c7 [2] fd dd [2] e3 c0 [2] e1 c1 [2] fa c7 [2] e6 c0 [2] fa ef }

  condition:
    any of them
}