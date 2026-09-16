rule TTP_XOR_QUAD_CurrentVersionRun_ebab {
  strings:
    $key_ebab = { b8 c4 [2] 9c ca [2] b7 e6 [2] 99 c4 [2] 8d df [2] 82 c5 [2] 9c d8 [2] 9e d9 [2] 85 df [2] 99 d8 [2] 85 f7 }

  condition:
    any of them
}