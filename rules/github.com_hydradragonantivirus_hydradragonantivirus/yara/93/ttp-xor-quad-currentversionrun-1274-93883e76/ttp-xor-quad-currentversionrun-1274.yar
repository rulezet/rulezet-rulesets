rule TTP_XOR_QUAD_CurrentVersionRun_1274 {
  strings:
    $key_1274 = { 41 1b [2] 65 15 [2] 4e 39 [2] 60 1b [2] 74 00 [2] 7b 1a [2] 65 07 [2] 67 06 [2] 7c 00 [2] 60 07 [2] 7c 28 }

  condition:
    any of them
}