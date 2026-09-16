rule TTP_XOR_QUAD_CurrentVersionRun_1d44 {
  strings:
    $key_1d44 = { 4e 2b [2] 6a 25 [2] 41 09 [2] 6f 2b [2] 7b 30 [2] 74 2a [2] 6a 37 [2] 68 36 [2] 73 30 [2] 6f 37 [2] 73 18 }

  condition:
    any of them
}