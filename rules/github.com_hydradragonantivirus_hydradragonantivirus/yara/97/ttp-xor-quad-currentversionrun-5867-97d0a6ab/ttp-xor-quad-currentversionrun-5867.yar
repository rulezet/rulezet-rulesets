rule TTP_XOR_QUAD_CurrentVersionRun_5867 {
  strings:
    $key_5867 = { 0b 08 [2] 2f 06 [2] 04 2a [2] 2a 08 [2] 3e 13 [2] 31 09 [2] 2f 14 [2] 2d 15 [2] 36 13 [2] 2a 14 [2] 36 3b }

  condition:
    any of them
}