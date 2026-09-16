rule TTP_XOR_QUAD_CurrentVersionRun_98b2 {
  strings:
    $key_98b2 = { cb dd [2] ef d3 [2] c4 ff [2] ea dd [2] fe c6 [2] f1 dc [2] ef c1 [2] ed c0 [2] f6 c6 [2] ea c1 [2] f6 ee }

  condition:
    any of them
}