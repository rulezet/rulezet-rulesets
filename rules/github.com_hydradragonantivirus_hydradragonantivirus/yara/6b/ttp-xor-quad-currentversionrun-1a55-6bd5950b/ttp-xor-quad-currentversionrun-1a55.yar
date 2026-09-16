rule TTP_XOR_QUAD_CurrentVersionRun_1a55 {
  strings:
    $key_1a55 = { 49 3a [2] 6d 34 [2] 46 18 [2] 68 3a [2] 7c 21 [2] 73 3b [2] 6d 26 [2] 6f 27 [2] 74 21 [2] 68 26 [2] 74 09 }

  condition:
    any of them
}