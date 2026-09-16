rule TTP_XOR_QUAD_CurrentVersionRun_1d45 {
  strings:
    $key_1d45 = { 4e 2a [2] 6a 24 [2] 41 08 [2] 6f 2a [2] 7b 31 [2] 74 2b [2] 6a 36 [2] 68 37 [2] 73 31 [2] 6f 36 [2] 73 19 }

  condition:
    any of them
}