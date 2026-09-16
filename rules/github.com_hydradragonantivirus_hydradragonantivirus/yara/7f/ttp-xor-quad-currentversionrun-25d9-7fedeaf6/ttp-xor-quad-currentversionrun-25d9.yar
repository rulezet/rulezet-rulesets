rule TTP_XOR_QUAD_CurrentVersionRun_25d9 {
  strings:
    $key_25d9 = { 76 b6 [2] 52 b8 [2] 79 94 [2] 57 b6 [2] 43 ad [2] 4c b7 [2] 52 aa [2] 50 ab [2] 4b ad [2] 57 aa [2] 4b 85 }

  condition:
    any of them
}