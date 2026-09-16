rule TTP_XOR_QUAD_CurrentVersionRun_f5c5 {
  strings:
    $key_f5c5 = { a6 aa [2] 82 a4 [2] a9 88 [2] 87 aa [2] 93 b1 [2] 9c ab [2] 82 b6 [2] 80 b7 [2] 9b b1 [2] 87 b6 [2] 9b 99 }

  condition:
    any of them
}