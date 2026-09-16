rule TTP_XOR_QUAD_CurrentVersionRun_66c5 {
  strings:
    $key_66c5 = { 35 aa [2] 11 a4 [2] 3a 88 [2] 14 aa [2] 00 b1 [2] 0f ab [2] 11 b6 [2] 13 b7 [2] 08 b1 [2] 14 b6 [2] 08 99 }

  condition:
    any of them
}