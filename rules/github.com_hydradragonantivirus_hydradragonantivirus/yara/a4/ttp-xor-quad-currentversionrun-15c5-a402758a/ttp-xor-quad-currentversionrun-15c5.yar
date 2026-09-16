rule TTP_XOR_QUAD_CurrentVersionRun_15c5 {
  strings:
    $key_15c5 = { 46 aa [2] 62 a4 [2] 49 88 [2] 67 aa [2] 73 b1 [2] 7c ab [2] 62 b6 [2] 60 b7 [2] 7b b1 [2] 67 b6 [2] 7b 99 }

  condition:
    any of them
}