rule TTP_XOR_QUAD_CurrentVersionRun_7bd9 {
  strings:
    $key_7bd9 = { 28 b6 [2] 0c b8 [2] 27 94 [2] 09 b6 [2] 1d ad [2] 12 b7 [2] 0c aa [2] 0e ab [2] 15 ad [2] 09 aa [2] 15 85 }

  condition:
    any of them
}