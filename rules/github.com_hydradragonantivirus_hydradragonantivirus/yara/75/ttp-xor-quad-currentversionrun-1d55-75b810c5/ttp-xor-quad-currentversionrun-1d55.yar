rule TTP_XOR_QUAD_CurrentVersionRun_1d55 {
  strings:
    $key_1d55 = { 4e 3a [2] 6a 34 [2] 41 18 [2] 6f 3a [2] 7b 21 [2] 74 3b [2] 6a 26 [2] 68 27 [2] 73 21 [2] 6f 26 [2] 73 09 }

  condition:
    any of them
}