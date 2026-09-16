rule TTP_XOR_QUAD_CurrentVersionRun_6707 {
  strings:
    $key_6707 = { 34 68 [2] 10 66 [2] 3b 4a [2] 15 68 [2] 01 73 [2] 0e 69 [2] 10 74 [2] 12 75 [2] 09 73 [2] 15 74 [2] 09 5b }

  condition:
    any of them
}