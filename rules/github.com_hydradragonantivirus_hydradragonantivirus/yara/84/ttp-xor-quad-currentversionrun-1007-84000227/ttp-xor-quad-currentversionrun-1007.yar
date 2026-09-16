rule TTP_XOR_QUAD_CurrentVersionRun_1007 {
  strings:
    $key_1007 = { 43 68 [2] 67 66 [2] 4c 4a [2] 62 68 [2] 76 73 [2] 79 69 [2] 67 74 [2] 65 75 [2] 7e 73 [2] 62 74 [2] 7e 5b }

  condition:
    any of them
}