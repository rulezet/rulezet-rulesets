rule TTP_XOR_QUAD_CurrentVersionRun_cabb {
  strings:
    $key_cabb = { 99 d4 [2] bd da [2] 96 f6 [2] b8 d4 [2] ac cf [2] a3 d5 [2] bd c8 [2] bf c9 [2] a4 cf [2] b8 c8 [2] a4 e7 }

  condition:
    any of them
}