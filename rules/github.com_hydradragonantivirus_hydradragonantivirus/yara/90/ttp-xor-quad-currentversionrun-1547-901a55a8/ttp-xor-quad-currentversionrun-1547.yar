rule TTP_XOR_QUAD_CurrentVersionRun_1547 {
  strings:
    $key_1547 = { 46 28 [2] 62 26 [2] 49 0a [2] 67 28 [2] 73 33 [2] 7c 29 [2] 62 34 [2] 60 35 [2] 7b 33 [2] 67 34 [2] 7b 1b }

  condition:
    any of them
}