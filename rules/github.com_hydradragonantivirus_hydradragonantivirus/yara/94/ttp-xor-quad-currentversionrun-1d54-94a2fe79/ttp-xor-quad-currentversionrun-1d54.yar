rule TTP_XOR_QUAD_CurrentVersionRun_1d54 {
  strings:
    $key_1d54 = { 4e 3b [2] 6a 35 [2] 41 19 [2] 6f 3b [2] 7b 20 [2] 74 3a [2] 6a 27 [2] 68 26 [2] 73 20 [2] 6f 27 [2] 73 08 }

  condition:
    any of them
}