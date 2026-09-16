rule TTP_XOR_QUAD_CurrentVersionRun_60d9 {
  strings:
    $key_60d9 = { 33 b6 [2] 17 b8 [2] 3c 94 [2] 12 b6 [2] 06 ad [2] 09 b7 [2] 17 aa [2] 15 ab [2] 0e ad [2] 12 aa [2] 0e 85 }

  condition:
    any of them
}