rule TTP_XOR_QUAD_CurrentVersionRun_2ed9 {
  strings:
    $key_2ed9 = { 7d b6 [2] 59 b8 [2] 72 94 [2] 5c b6 [2] 48 ad [2] 47 b7 [2] 59 aa [2] 5b ab [2] 40 ad [2] 5c aa [2] 40 85 }

  condition:
    any of them
}