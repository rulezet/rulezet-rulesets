rule TTP_XOR_QUAD_CurrentVersionRun_28df {
  strings:
    $key_28df = { 7b b0 [2] 5f be [2] 74 92 [2] 5a b0 [2] 4e ab [2] 41 b1 [2] 5f ac [2] 5d ad [2] 46 ab [2] 5a ac [2] 46 83 }

  condition:
    any of them
}