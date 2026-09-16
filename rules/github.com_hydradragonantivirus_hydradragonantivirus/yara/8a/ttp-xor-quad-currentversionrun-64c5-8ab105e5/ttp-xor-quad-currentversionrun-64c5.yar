rule TTP_XOR_QUAD_CurrentVersionRun_64c5 {
  strings:
    $key_64c5 = { 37 aa [2] 13 a4 [2] 38 88 [2] 16 aa [2] 02 b1 [2] 0d ab [2] 13 b6 [2] 11 b7 [2] 0a b1 [2] 16 b6 [2] 0a 99 }

  condition:
    any of them
}