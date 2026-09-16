rule TTP_XOR_QUAD_CurrentVersionRun_3867 {
  strings:
    $key_3867 = { 6b 08 [2] 4f 06 [2] 64 2a [2] 4a 08 [2] 5e 13 [2] 51 09 [2] 4f 14 [2] 4d 15 [2] 56 13 [2] 4a 14 [2] 56 3b }

  condition:
    any of them
}