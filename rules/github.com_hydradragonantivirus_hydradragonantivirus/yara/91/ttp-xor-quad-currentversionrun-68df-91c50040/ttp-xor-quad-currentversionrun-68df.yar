rule TTP_XOR_QUAD_CurrentVersionRun_68df {
  strings:
    $key_68df = { 3b b0 [2] 1f be [2] 34 92 [2] 1a b0 [2] 0e ab [2] 01 b1 [2] 1f ac [2] 1d ad [2] 06 ab [2] 1a ac [2] 06 83 }

  condition:
    any of them
}