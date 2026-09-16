rule TTP_XOR_QUAD_CurrentVersionRun_76b2 {
  strings:
    $key_76b2 = { 25 dd [2] 01 d3 [2] 2a ff [2] 04 dd [2] 10 c6 [2] 1f dc [2] 01 c1 [2] 03 c0 [2] 18 c6 [2] 04 c1 [2] 18 ee }

  condition:
    any of them
}