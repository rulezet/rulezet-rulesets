rule TTP_XOR_QUAD_CurrentVersionRun_16b2 {
  strings:
    $key_16b2 = { 45 dd [2] 61 d3 [2] 4a ff [2] 64 dd [2] 70 c6 [2] 7f dc [2] 61 c1 [2] 63 c0 [2] 78 c6 [2] 64 c1 [2] 78 ee }

  condition:
    any of them
}