rule TTP_XOR_QUAD_CurrentVersionRun_1d65 {
  strings:
    $key_1d65 = { 4e 0a [2] 6a 04 [2] 41 28 [2] 6f 0a [2] 7b 11 [2] 74 0b [2] 6a 16 [2] 68 17 [2] 73 11 [2] 6f 16 [2] 73 39 }

  condition:
    any of them
}