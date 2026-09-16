rule TTP_XOR_QUAD_CurrentVersionRun_38df {
  strings:
    $key_38df = { 6b b0 [2] 4f be [2] 64 92 [2] 4a b0 [2] 5e ab [2] 51 b1 [2] 4f ac [2] 4d ad [2] 56 ab [2] 4a ac [2] 56 83 }

  condition:
    any of them
}