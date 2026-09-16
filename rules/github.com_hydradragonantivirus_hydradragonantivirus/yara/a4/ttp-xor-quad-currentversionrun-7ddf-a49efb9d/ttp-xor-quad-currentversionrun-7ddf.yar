rule TTP_XOR_QUAD_CurrentVersionRun_7ddf {
  strings:
    $key_7ddf = { 2e b0 [2] 0a be [2] 21 92 [2] 0f b0 [2] 1b ab [2] 14 b1 [2] 0a ac [2] 08 ad [2] 13 ab [2] 0f ac [2] 13 83 }

  condition:
    any of them
}