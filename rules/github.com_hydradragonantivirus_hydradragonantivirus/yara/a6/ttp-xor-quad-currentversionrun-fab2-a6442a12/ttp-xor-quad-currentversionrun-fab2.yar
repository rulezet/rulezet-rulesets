rule TTP_XOR_QUAD_CurrentVersionRun_fab2 {
  strings:
    $key_fab2 = { a9 dd [2] 8d d3 [2] a6 ff [2] 88 dd [2] 9c c6 [2] 93 dc [2] 8d c1 [2] 8f c0 [2] 94 c6 [2] 88 c1 [2] 94 ee }

  condition:
    any of them
}