rule TTP_XOR_QUAD_CurrentVersionRun_2167 {
  strings:
    $key_2167 = { 72 08 [2] 56 06 [2] 7d 2a [2] 53 08 [2] 47 13 [2] 48 09 [2] 56 14 [2] 54 15 [2] 4f 13 [2] 53 14 [2] 4f 3b }

  condition:
    any of them
}