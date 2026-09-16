rule TTP_XOR_QUAD_CurrentVersionRun_1d69 {
  strings:
    $key_1d69 = { 4e 06 [2] 6a 08 [2] 41 24 [2] 6f 06 [2] 7b 1d [2] 74 07 [2] 6a 1a [2] 68 1b [2] 73 1d [2] 6f 1a [2] 73 35 }

  condition:
    any of them
}