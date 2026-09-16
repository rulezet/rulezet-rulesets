rule TTP_XOR_QUAD_CurrentVersionRun_1054 {
  strings:
    $key_1054 = { 43 3b [2] 67 35 [2] 4c 19 [2] 62 3b [2] 76 20 [2] 79 3a [2] 67 27 [2] 65 26 [2] 7e 20 [2] 62 27 [2] 7e 08 }

  condition:
    any of them
}