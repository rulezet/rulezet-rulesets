rule TTP_XOR_QUAD_CurrentVersionRun_0167 {
  strings:
    $key_0167 = { 52 08 [2] 76 06 [2] 5d 2a [2] 73 08 [2] 67 13 [2] 68 09 [2] 76 14 [2] 74 15 [2] 6f 13 [2] 73 14 [2] 6f 3b }

  condition:
    any of them
}