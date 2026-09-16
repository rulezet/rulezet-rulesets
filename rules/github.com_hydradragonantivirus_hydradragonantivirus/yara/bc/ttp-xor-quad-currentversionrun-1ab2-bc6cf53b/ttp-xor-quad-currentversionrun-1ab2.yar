rule TTP_XOR_QUAD_CurrentVersionRun_1ab2 {
  strings:
    $key_1ab2 = { 49 dd [2] 6d d3 [2] 46 ff [2] 68 dd [2] 7c c6 [2] 73 dc [2] 6d c1 [2] 6f c0 [2] 74 c6 [2] 68 c1 [2] 74 ee }

  condition:
    any of them
}