rule TTP_XOR_QUAD_CurrentVersionRun_1467 {
  strings:
    $key_1467 = { 47 08 [2] 63 06 [2] 48 2a [2] 66 08 [2] 72 13 [2] 7d 09 [2] 63 14 [2] 61 15 [2] 7a 13 [2] 66 14 [2] 7a 3b }

  condition:
    any of them
}