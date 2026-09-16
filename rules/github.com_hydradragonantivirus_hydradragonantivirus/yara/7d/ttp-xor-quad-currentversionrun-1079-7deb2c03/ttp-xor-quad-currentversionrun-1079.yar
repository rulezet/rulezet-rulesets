rule TTP_XOR_QUAD_CurrentVersionRun_1079 {
  strings:
    $key_1079 = { 43 16 [2] 67 18 [2] 4c 34 [2] 62 16 [2] 76 0d [2] 79 17 [2] 67 0a [2] 65 0b [2] 7e 0d [2] 62 0a [2] 7e 25 }

  condition:
    any of them
}