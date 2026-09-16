rule TTP_XOR_QUAD_CurrentVersionRun_1667 {
  strings:
    $key_1667 = { 45 08 [2] 61 06 [2] 4a 2a [2] 64 08 [2] 70 13 [2] 7f 09 [2] 61 14 [2] 63 15 [2] 78 13 [2] 64 14 [2] 78 3b }

  condition:
    any of them
}