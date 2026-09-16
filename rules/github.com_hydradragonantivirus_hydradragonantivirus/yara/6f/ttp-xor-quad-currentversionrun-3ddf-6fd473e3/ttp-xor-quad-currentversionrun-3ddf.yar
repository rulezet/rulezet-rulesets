rule TTP_XOR_QUAD_CurrentVersionRun_3ddf {
  strings:
    $key_3ddf = { 6e b0 [2] 4a be [2] 61 92 [2] 4f b0 [2] 5b ab [2] 54 b1 [2] 4a ac [2] 48 ad [2] 53 ab [2] 4f ac [2] 53 83 }

  condition:
    any of them
}