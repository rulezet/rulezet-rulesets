rule TTP_XOR_QUAD_CurrentVersionRun_6cdf {
  strings:
    $key_6cdf = { 3f b0 [2] 1b be [2] 30 92 [2] 1e b0 [2] 0a ab [2] 05 b1 [2] 1b ac [2] 19 ad [2] 02 ab [2] 1e ac [2] 02 83 }

  condition:
    any of them
}