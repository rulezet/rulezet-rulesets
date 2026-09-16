rule TTP_XOR_QUAD_CurrentVersionRun_66b2 {
  strings:
    $key_66b2 = { 35 dd [2] 11 d3 [2] 3a ff [2] 14 dd [2] 00 c6 [2] 0f dc [2] 11 c1 [2] 13 c0 [2] 08 c6 [2] 14 c1 [2] 08 ee }

  condition:
    any of them
}