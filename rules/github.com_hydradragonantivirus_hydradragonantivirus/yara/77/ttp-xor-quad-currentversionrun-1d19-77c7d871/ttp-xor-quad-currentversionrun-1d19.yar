rule TTP_XOR_QUAD_CurrentVersionRun_1d19 {
  strings:
    $key_1d19 = { 4e 76 [2] 6a 78 [2] 41 54 [2] 6f 76 [2] 7b 6d [2] 74 77 [2] 6a 6a [2] 68 6b [2] 73 6d [2] 6f 6a [2] 73 45 }

  condition:
    any of them
}