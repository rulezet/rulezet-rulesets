rule TTP_XOR_QUAD_CurrentVersionRun_2ddf {
  strings:
    $key_2ddf = { 7e b0 [2] 5a be [2] 71 92 [2] 5f b0 [2] 4b ab [2] 44 b1 [2] 5a ac [2] 58 ad [2] 43 ab [2] 5f ac [2] 43 83 }

  condition:
    any of them
}