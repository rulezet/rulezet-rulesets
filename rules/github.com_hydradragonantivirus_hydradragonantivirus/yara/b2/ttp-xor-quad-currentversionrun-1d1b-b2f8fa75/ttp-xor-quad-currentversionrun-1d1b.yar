rule TTP_XOR_QUAD_CurrentVersionRun_1d1b {
  strings:
    $key_1d1b = { 4e 74 [2] 6a 7a [2] 41 56 [2] 6f 74 [2] 7b 6f [2] 74 75 [2] 6a 68 [2] 68 69 [2] 73 6f [2] 6f 68 [2] 73 47 }

  condition:
    any of them
}