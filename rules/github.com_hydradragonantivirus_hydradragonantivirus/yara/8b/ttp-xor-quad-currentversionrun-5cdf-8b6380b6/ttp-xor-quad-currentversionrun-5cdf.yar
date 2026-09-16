rule TTP_XOR_QUAD_CurrentVersionRun_5cdf {
  strings:
    $key_5cdf = { 0f b0 [2] 2b be [2] 00 92 [2] 2e b0 [2] 3a ab [2] 35 b1 [2] 2b ac [2] 29 ad [2] 32 ab [2] 2e ac [2] 32 83 }

  condition:
    any of them
}