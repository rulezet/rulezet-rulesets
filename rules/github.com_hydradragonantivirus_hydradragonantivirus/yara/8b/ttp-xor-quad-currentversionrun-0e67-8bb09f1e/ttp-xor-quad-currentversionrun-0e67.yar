rule TTP_XOR_QUAD_CurrentVersionRun_0e67 {
  strings:
    $key_0e67 = { 5d 08 [2] 79 06 [2] 52 2a [2] 7c 08 [2] 68 13 [2] 67 09 [2] 79 14 [2] 7b 15 [2] 60 13 [2] 7c 14 [2] 60 3b }

  condition:
    any of them
}