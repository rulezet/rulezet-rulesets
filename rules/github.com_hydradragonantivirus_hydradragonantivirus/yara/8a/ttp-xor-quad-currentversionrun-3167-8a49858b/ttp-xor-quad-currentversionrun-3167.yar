rule TTP_XOR_QUAD_CurrentVersionRun_3167 {
  strings:
    $key_3167 = { 62 08 [2] 46 06 [2] 6d 2a [2] 43 08 [2] 57 13 [2] 58 09 [2] 46 14 [2] 44 15 [2] 5f 13 [2] 43 14 [2] 5f 3b }

  condition:
    any of them
}