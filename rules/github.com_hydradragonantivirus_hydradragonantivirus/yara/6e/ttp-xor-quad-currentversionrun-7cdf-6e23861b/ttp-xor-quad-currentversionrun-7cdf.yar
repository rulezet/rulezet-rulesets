rule TTP_XOR_QUAD_CurrentVersionRun_7cdf {
  strings:
    $key_7cdf = { 2f b0 [2] 0b be [2] 20 92 [2] 0e b0 [2] 1a ab [2] 15 b1 [2] 0b ac [2] 09 ad [2] 12 ab [2] 0e ac [2] 12 83 }

  condition:
    any of them
}