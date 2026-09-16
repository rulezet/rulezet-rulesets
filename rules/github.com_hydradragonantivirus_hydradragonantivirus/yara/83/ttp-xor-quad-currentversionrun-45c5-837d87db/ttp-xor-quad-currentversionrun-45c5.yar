rule TTP_XOR_QUAD_CurrentVersionRun_45c5 {
  strings:
    $key_45c5 = { 16 aa [2] 32 a4 [2] 19 88 [2] 37 aa [2] 23 b1 [2] 2c ab [2] 32 b6 [2] 30 b7 [2] 2b b1 [2] 37 b6 [2] 2b 99 }

  condition:
    any of them
}