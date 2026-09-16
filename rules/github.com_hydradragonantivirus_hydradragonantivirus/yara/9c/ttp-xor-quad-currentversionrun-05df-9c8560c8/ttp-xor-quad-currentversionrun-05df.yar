rule TTP_XOR_QUAD_CurrentVersionRun_05df {
  strings:
    $key_05df = { 56 b0 [2] 72 be [2] 59 92 [2] 77 b0 [2] 63 ab [2] 6c b1 [2] 72 ac [2] 70 ad [2] 6b ab [2] 77 ac [2] 6b 83 }

  condition:
    any of them
}