rule TTP_XOR_QUAD_CurrentVersionRun_1d79 {
  strings:
    $key_1d79 = { 4e 16 [2] 6a 18 [2] 41 34 [2] 6f 16 [2] 7b 0d [2] 74 17 [2] 6a 0a [2] 68 0b [2] 73 0d [2] 6f 0a [2] 73 25 }

  condition:
    any of them
}