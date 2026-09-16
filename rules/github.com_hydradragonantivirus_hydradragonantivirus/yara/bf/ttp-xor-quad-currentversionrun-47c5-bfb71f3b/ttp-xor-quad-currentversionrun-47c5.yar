rule TTP_XOR_QUAD_CurrentVersionRun_47c5 {
  strings:
    $key_47c5 = { 14 aa [2] 30 a4 [2] 1b 88 [2] 35 aa [2] 21 b1 [2] 2e ab [2] 30 b6 [2] 32 b7 [2] 29 b1 [2] 35 b6 [2] 29 99 }

  condition:
    any of them
}