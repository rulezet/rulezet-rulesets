rule TTP_XOR_QUAD_CurrentVersionRun_1d2b {
  strings:
    $key_1d2b = { 4e 44 [2] 6a 4a [2] 41 66 [2] 6f 44 [2] 7b 5f [2] 74 45 [2] 6a 58 [2] 68 59 [2] 73 5f [2] 6f 58 [2] 73 77 }

  condition:
    any of them
}