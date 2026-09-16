rule TTP_XOR_QUAD_CurrentVersionRun_c586 {
  strings:
    $key_c586 = { 96 e9 [2] b2 e7 [2] 99 cb [2] b7 e9 [2] a3 f2 [2] ac e8 [2] b2 f5 [2] b0 f4 [2] ab f2 [2] b7 f5 [2] ab da }

  condition:
    any of them
}