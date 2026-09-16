rule TTP_XOR_QUAD_CurrentVersionRun_94d3 {
  strings:
    $key_94d3 = { c7 bc [2] e3 b2 [2] c8 9e [2] e6 bc [2] f2 a7 [2] fd bd [2] e3 a0 [2] e1 a1 [2] fa a7 [2] e6 a0 [2] fa 8f }

  condition:
    any of them
}