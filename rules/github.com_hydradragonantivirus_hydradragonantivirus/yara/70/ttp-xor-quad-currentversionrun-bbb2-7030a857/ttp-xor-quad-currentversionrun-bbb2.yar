rule TTP_XOR_QUAD_CurrentVersionRun_bbb2 {
  strings:
    $key_bbb2 = { e8 dd [2] cc d3 [2] e7 ff [2] c9 dd [2] dd c6 [2] d2 dc [2] cc c1 [2] ce c0 [2] d5 c6 [2] c9 c1 [2] d5 ee }

  condition:
    any of them
}