rule TTP_XOR_QUAD_CurrentVersionRun_4ddf {
  strings:
    $key_4ddf = { 1e b0 [2] 3a be [2] 11 92 [2] 3f b0 [2] 2b ab [2] 24 b1 [2] 3a ac [2] 38 ad [2] 23 ab [2] 3f ac [2] 23 83 }

  condition:
    any of them
}