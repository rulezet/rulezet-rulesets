rule TTP_XOR_QUAD_CurrentVersionRun_c481 {
  strings:
    $key_c481 = { 97 ee [2] b3 e0 [2] 98 cc [2] b6 ee [2] a2 f5 [2] ad ef [2] b3 f2 [2] b1 f3 [2] aa f5 [2] b6 f2 [2] aa dd }

  condition:
    any of them
}