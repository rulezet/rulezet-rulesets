rule TTP_XOR_QUAD_CurrentVersionRun_25c5 {
  strings:
    $key_25c5 = { 76 aa [2] 52 a4 [2] 79 88 [2] 57 aa [2] 43 b1 [2] 4c ab [2] 52 b6 [2] 50 b7 [2] 4b b1 [2] 57 b6 [2] 4b 99 }

  condition:
    any of them
}