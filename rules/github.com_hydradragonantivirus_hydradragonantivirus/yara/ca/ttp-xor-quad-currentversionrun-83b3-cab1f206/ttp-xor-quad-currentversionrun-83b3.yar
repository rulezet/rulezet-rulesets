rule TTP_XOR_QUAD_CurrentVersionRun_83b3 {
  strings:
    $key_83b3 = { d0 dc [2] f4 d2 [2] df fe [2] f1 dc [2] e5 c7 [2] ea dd [2] f4 c0 [2] f6 c1 [2] ed c7 [2] f1 c0 [2] ed ef }

  condition:
    any of them
}