rule TTP_XOR_QUAD_CurrentVersionRun_dec8 {
  strings:
    $key_dec8 = { 8d a7 [2] a9 a9 [2] 82 85 [2] ac a7 [2] b8 bc [2] b7 a6 [2] a9 bb [2] ab ba [2] b0 bc [2] ac bb [2] b0 94 }

  condition:
    any of them
}