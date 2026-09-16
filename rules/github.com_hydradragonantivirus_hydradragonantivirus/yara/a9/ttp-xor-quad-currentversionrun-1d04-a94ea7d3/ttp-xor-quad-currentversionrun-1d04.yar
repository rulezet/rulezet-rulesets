rule TTP_XOR_QUAD_CurrentVersionRun_1d04 {
  strings:
    $key_1d04 = { 4e 6b [2] 6a 65 [2] 41 49 [2] 6f 6b [2] 7b 70 [2] 74 6a [2] 6a 77 [2] 68 76 [2] 73 70 [2] 6f 77 [2] 73 58 }

  condition:
    any of them
}