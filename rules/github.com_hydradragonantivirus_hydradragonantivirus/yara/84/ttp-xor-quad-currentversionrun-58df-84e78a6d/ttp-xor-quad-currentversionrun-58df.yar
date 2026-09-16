rule TTP_XOR_QUAD_CurrentVersionRun_58df {
  strings:
    $key_58df = { 0b b0 [2] 2f be [2] 04 92 [2] 2a b0 [2] 3e ab [2] 31 b1 [2] 2f ac [2] 2d ad [2] 36 ab [2] 2a ac [2] 36 83 }

  condition:
    any of them
}