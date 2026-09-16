rule TTP_XOR_QUAD_CurrentVersionRun_dfba {
  strings:
    $key_dfba = { 8c d5 [2] a8 db [2] 83 f7 [2] ad d5 [2] b9 ce [2] b6 d4 [2] a8 c9 [2] aa c8 [2] b1 ce [2] ad c9 [2] b1 e6 }

  condition:
    any of them
}