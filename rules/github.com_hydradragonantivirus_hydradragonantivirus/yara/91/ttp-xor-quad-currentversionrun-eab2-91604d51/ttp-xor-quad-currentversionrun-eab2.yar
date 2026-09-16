rule TTP_XOR_QUAD_CurrentVersionRun_eab2 {
  strings:
    $key_eab2 = { b9 dd [2] 9d d3 [2] b6 ff [2] 98 dd [2] 8c c6 [2] 83 dc [2] 9d c1 [2] 9f c0 [2] 84 c6 [2] 98 c1 [2] 84 ee }

  condition:
    any of them
}