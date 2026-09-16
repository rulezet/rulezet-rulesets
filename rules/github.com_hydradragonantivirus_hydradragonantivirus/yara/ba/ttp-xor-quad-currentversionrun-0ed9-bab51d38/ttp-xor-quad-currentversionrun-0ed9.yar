rule TTP_XOR_QUAD_CurrentVersionRun_0ed9 {
  strings:
    $key_0ed9 = { 5d b6 [2] 79 b8 [2] 52 94 [2] 7c b6 [2] 68 ad [2] 67 b7 [2] 79 aa [2] 7b ab [2] 60 ad [2] 7c aa [2] 60 85 }

  condition:
    any of them
}