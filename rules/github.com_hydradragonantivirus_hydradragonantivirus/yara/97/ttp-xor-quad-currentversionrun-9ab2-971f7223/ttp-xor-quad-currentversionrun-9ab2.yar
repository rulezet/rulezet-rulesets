rule TTP_XOR_QUAD_CurrentVersionRun_9ab2 {
  strings:
    $key_9ab2 = { c9 dd [2] ed d3 [2] c6 ff [2] e8 dd [2] fc c6 [2] f3 dc [2] ed c1 [2] ef c0 [2] f4 c6 [2] e8 c1 [2] f4 ee }

  condition:
    any of them
}