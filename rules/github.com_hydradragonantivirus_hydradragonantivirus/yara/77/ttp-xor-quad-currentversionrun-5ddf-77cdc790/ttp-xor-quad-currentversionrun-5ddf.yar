rule TTP_XOR_QUAD_CurrentVersionRun_5ddf {
  strings:
    $key_5ddf = { 0e b0 [2] 2a be [2] 01 92 [2] 2f b0 [2] 3b ab [2] 34 b1 [2] 2a ac [2] 28 ad [2] 33 ab [2] 2f ac [2] 33 83 }

  condition:
    any of them
}