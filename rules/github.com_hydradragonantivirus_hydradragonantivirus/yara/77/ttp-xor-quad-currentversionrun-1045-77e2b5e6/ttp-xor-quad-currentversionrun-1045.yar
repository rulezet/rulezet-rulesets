rule TTP_XOR_QUAD_CurrentVersionRun_1045 {
  strings:
    $key_1045 = { 43 2a [2] 67 24 [2] 4c 08 [2] 62 2a [2] 76 31 [2] 79 2b [2] 67 36 [2] 65 37 [2] 7e 31 [2] 62 36 [2] 7e 19 }

  condition:
    any of them
}