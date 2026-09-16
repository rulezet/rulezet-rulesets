rule TTP_XOR_QUAD_CurrentVersionRun_2854 {
  strings:
    $key_2854 = { 7b 3b [2] 5f 35 [2] 74 19 [2] 5a 3b [2] 4e 20 [2] 41 3a [2] 5f 27 [2] 5d 26 [2] 46 20 [2] 5a 27 [2] 46 08 }

  condition:
    any of them
}