rule TTP_XOR_QUAD_CurrentVersionRun_bbbc {
  strings:
    $key_bbbc = { e8 d3 [2] cc dd [2] e7 f1 [2] c9 d3 [2] dd c8 [2] d2 d2 [2] cc cf [2] ce ce [2] d5 c8 [2] c9 cf [2] d5 e0 }

  condition:
    any of them
}