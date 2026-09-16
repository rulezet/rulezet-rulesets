rule TTP_XOR_QUAD_CurrentVersionRun_1ed9 {
  strings:
    $key_1ed9 = { 4d b6 [2] 69 b8 [2] 42 94 [2] 6c b6 [2] 78 ad [2] 77 b7 [2] 69 aa [2] 6b ab [2] 70 ad [2] 6c aa [2] 70 85 }

  condition:
    any of them
}