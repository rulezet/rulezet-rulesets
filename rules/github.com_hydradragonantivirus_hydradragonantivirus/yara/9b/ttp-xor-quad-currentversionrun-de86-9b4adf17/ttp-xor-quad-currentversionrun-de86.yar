rule TTP_XOR_QUAD_CurrentVersionRun_de86 {
  strings:
    $key_de86 = { 8d e9 [2] a9 e7 [2] 82 cb [2] ac e9 [2] b8 f2 [2] b7 e8 [2] a9 f5 [2] ab f4 [2] b0 f2 [2] ac f5 [2] b0 da }

  condition:
    any of them
}