rule TTP_XOR_QUAD_CurrentVersionRun_fddf {
  strings:
    $key_fddf = { ae b0 [2] 8a be [2] a1 92 [2] 8f b0 [2] 9b ab [2] 94 b1 [2] 8a ac [2] 88 ad [2] 93 ab [2] 8f ac [2] 93 83 }

  condition:
    any of them
}