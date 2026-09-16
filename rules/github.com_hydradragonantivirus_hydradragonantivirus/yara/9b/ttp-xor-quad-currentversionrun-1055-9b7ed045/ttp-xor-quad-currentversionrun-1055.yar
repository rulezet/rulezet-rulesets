rule TTP_XOR_QUAD_CurrentVersionRun_1055 {
  strings:
    $key_1055 = { 43 3a [2] 67 34 [2] 4c 18 [2] 62 3a [2] 76 21 [2] 79 3b [2] 67 26 [2] 65 27 [2] 7e 21 [2] 62 26 [2] 7e 09 }

  condition:
    any of them
}