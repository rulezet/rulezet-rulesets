rule TTP_XOR_QUAD_CurrentVersionRun_00df {
  strings:
    $key_00df = { 53 b0 [2] 77 be [2] 5c 92 [2] 72 b0 [2] 66 ab [2] 69 b1 [2] 77 ac [2] 75 ad [2] 6e ab [2] 72 ac [2] 6e 83 }

  condition:
    any of them
}