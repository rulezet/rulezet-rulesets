rule TTP_XOR_QUAD_CurrentVersionRun_1267 {
  strings:
    $key_1267 = { 41 08 [2] 65 06 [2] 4e 2a [2] 60 08 [2] 74 13 [2] 7b 09 [2] 65 14 [2] 67 15 [2] 7c 13 [2] 60 14 [2] 7c 3b }

  condition:
    any of them
}