rule TTP_XOR_QUAD_CurrentVersionRun_65d9 {
  strings:
    $key_65d9 = { 36 b6 [2] 12 b8 [2] 39 94 [2] 17 b6 [2] 03 ad [2] 0c b7 [2] 12 aa [2] 10 ab [2] 0b ad [2] 17 aa [2] 0b 85 }

  condition:
    any of them
}