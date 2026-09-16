rule TTP_XOR_QUAD_CurrentVersionRun_ccdf {
  strings:
    $key_ccdf = { 9f b0 [2] bb be [2] 90 92 [2] be b0 [2] aa ab [2] a5 b1 [2] bb ac [2] b9 ad [2] a2 ab [2] be ac [2] a2 83 }

  condition:
    any of them
}