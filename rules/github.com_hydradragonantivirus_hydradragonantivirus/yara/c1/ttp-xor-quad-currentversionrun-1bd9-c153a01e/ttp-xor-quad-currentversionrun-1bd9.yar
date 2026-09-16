rule TTP_XOR_QUAD_CurrentVersionRun_1bd9 {
  strings:
    $key_1bd9 = { 48 b6 [2] 6c b8 [2] 47 94 [2] 69 b6 [2] 7d ad [2] 72 b7 [2] 6c aa [2] 6e ab [2] 75 ad [2] 69 aa [2] 75 85 }

  condition:
    any of them
}