rule TTP_XOR_QUAD_CurrentVersionRun_fcdf {
  strings:
    $key_fcdf = { af b0 [2] 8b be [2] a0 92 [2] 8e b0 [2] 9a ab [2] 95 b1 [2] 8b ac [2] 89 ad [2] 92 ab [2] 8e ac [2] 92 83 }

  condition:
    any of them
}