rule TTP_XOR_QUAD_CurrentVersionRun_4607 {
  strings:
    $key_4607 = { 15 68 [2] 31 66 [2] 1a 4a [2] 34 68 [2] 20 73 [2] 2f 69 [2] 31 74 [2] 33 75 [2] 28 73 [2] 34 74 [2] 28 5b }

  condition:
    any of them
}