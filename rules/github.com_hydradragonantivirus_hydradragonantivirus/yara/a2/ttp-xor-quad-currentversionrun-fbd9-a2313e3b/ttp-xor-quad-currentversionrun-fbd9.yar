rule TTP_XOR_QUAD_CurrentVersionRun_fbd9 {
  strings:
    $key_fbd9 = { a8 b6 [2] 8c b8 [2] a7 94 [2] 89 b6 [2] 9d ad [2] 92 b7 [2] 8c aa [2] 8e ab [2] 95 ad [2] 89 aa [2] 95 85 }

  condition:
    any of them
}