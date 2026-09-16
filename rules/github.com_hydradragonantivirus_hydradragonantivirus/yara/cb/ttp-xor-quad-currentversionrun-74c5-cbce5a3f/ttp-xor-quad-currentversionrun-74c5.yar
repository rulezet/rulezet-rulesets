rule TTP_XOR_QUAD_CurrentVersionRun_74c5 {
  strings:
    $key_74c5 = { 27 aa [2] 03 a4 [2] 28 88 [2] 06 aa [2] 12 b1 [2] 1d ab [2] 03 b6 [2] 01 b7 [2] 1a b1 [2] 06 b6 [2] 1a 99 }

  condition:
    any of them
}