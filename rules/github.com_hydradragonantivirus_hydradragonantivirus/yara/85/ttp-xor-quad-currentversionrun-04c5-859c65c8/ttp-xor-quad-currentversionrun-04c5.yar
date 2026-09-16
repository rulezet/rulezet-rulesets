rule TTP_XOR_QUAD_CurrentVersionRun_04c5 {
  strings:
    $key_04c5 = { 57 aa [2] 73 a4 [2] 58 88 [2] 76 aa [2] 62 b1 [2] 6d ab [2] 73 b6 [2] 71 b7 [2] 6a b1 [2] 76 b6 [2] 6a 99 }

  condition:
    any of them
}