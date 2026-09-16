rule TTP_XOR_QUAD_CurrentVersionRun_2667 {
  strings:
    $key_2667 = { 75 08 [2] 51 06 [2] 7a 2a [2] 54 08 [2] 40 13 [2] 4f 09 [2] 51 14 [2] 53 15 [2] 48 13 [2] 54 14 [2] 48 3b }

  condition:
    any of them
}