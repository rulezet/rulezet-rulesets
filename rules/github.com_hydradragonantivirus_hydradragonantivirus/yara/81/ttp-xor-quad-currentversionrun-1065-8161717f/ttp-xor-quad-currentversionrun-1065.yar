rule TTP_XOR_QUAD_CurrentVersionRun_1065 {
  strings:
    $key_1065 = { 43 0a [2] 67 04 [2] 4c 28 [2] 62 0a [2] 76 11 [2] 79 0b [2] 67 16 [2] 65 17 [2] 7e 11 [2] 62 16 [2] 7e 39 }

  condition:
    any of them
}