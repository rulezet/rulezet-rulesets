rule TTP_XOR_QUAD_CurrentVersionRun_76c5 {
  strings:
    $key_76c5 = { 25 aa [2] 01 a4 [2] 2a 88 [2] 04 aa [2] 10 b1 [2] 1f ab [2] 01 b6 [2] 03 b7 [2] 18 b1 [2] 04 b6 [2] 18 99 }

  condition:
    any of them
}