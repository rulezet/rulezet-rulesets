rule TTP_XOR_QUAD_CurrentVersionRun_7ed9 {
  strings:
    $key_7ed9 = { 2d b6 [2] 09 b8 [2] 22 94 [2] 0c b6 [2] 18 ad [2] 17 b7 [2] 09 aa [2] 0b ab [2] 10 ad [2] 0c aa [2] 10 85 }

  condition:
    any of them
}