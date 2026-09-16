rule TTP_XOR_QUAD_CurrentVersionRun_05c3 {
  strings:
    $key_05c3 = { 56 ac [2] 72 a2 [2] 59 8e [2] 77 ac [2] 63 b7 [2] 6c ad [2] 72 b0 [2] 70 b1 [2] 6b b7 [2] 77 b0 [2] 6b 9f }

  condition:
    any of them
}