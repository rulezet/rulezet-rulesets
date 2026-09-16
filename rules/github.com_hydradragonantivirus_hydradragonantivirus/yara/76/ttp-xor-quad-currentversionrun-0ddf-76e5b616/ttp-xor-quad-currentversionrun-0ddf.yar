rule TTP_XOR_QUAD_CurrentVersionRun_0ddf {
  strings:
    $key_0ddf = { 5e b0 [2] 7a be [2] 51 92 [2] 7f b0 [2] 6b ab [2] 64 b1 [2] 7a ac [2] 78 ad [2] 63 ab [2] 7f ac [2] 63 83 }

  condition:
    any of them
}