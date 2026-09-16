rule TTP_XOR_QUAD_CurrentVersionRun_08df {
  strings:
    $key_08df = { 5b b0 [2] 7f be [2] 54 92 [2] 7a b0 [2] 6e ab [2] 61 b1 [2] 7f ac [2] 7d ad [2] 66 ab [2] 7a ac [2] 66 83 }

  condition:
    any of them
}