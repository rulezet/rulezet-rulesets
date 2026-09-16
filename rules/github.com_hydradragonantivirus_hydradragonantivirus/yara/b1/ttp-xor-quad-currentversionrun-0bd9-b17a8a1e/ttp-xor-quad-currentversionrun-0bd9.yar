rule TTP_XOR_QUAD_CurrentVersionRun_0bd9 {
  strings:
    $key_0bd9 = { 58 b6 [2] 7c b8 [2] 57 94 [2] 79 b6 [2] 6d ad [2] 62 b7 [2] 7c aa [2] 7e ab [2] 65 ad [2] 79 aa [2] 65 85 }

  condition:
    any of them
}