rule TTP_XOR_QUAD_CurrentVersionRun_fed9 {
  strings:
    $key_fed9 = { ad b6 [2] 89 b8 [2] a2 94 [2] 8c b6 [2] 98 ad [2] 97 b7 [2] 89 aa [2] 8b ab [2] 90 ad [2] 8c aa [2] 90 85 }

  condition:
    any of them
}