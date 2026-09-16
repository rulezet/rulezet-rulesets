rule TTP_XOR_QUAD_CurrentVersionRun_73c4 {
  strings:
    $key_73c4 = { 20 ab [2] 04 a5 [2] 2f 89 [2] 01 ab [2] 15 b0 [2] 1a aa [2] 04 b7 [2] 06 b6 [2] 1d b0 [2] 01 b7 [2] 1d 98 }

  condition:
    any of them
}