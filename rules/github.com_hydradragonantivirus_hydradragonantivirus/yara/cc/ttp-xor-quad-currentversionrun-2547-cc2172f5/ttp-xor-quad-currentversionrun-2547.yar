rule TTP_XOR_QUAD_CurrentVersionRun_2547 {
  strings:
    $key_2547 = { 76 28 [2] 52 26 [2] 79 0a [2] 57 28 [2] 43 33 [2] 4c 29 [2] 52 34 [2] 50 35 [2] 4b 33 [2] 57 34 [2] 4b 1b }

  condition:
    any of them
}