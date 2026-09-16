rule TTP_XOR_QUAD_CurrentVersionRun_56c5 {
  strings:
    $key_56c5 = { 05 aa [2] 21 a4 [2] 0a 88 [2] 24 aa [2] 30 b1 [2] 3f ab [2] 21 b6 [2] 23 b7 [2] 38 b1 [2] 24 b6 [2] 38 99 }

  condition:
    any of them
}