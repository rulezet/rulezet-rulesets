rule TTP_XOR_QUAD_CurrentVersionRun_2867 {
  strings:
    $key_2867 = { 7b 08 [2] 5f 06 [2] 74 2a [2] 5a 08 [2] 4e 13 [2] 41 09 [2] 5f 14 [2] 5d 15 [2] 46 13 [2] 5a 14 [2] 46 3b }

  condition:
    any of them
}