rule TTP_XOR_QUAD_CurrentVersionRun_1577 {
  strings:
    $key_1577 = { 46 18 [2] 62 16 [2] 49 3a [2] 67 18 [2] 73 03 [2] 7c 19 [2] 62 04 [2] 60 05 [2] 7b 03 [2] 67 04 [2] 7b 2b }

  condition:
    any of them
}