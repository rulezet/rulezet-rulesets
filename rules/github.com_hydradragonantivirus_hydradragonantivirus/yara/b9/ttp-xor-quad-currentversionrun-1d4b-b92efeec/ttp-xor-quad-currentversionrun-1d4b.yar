rule TTP_XOR_QUAD_CurrentVersionRun_1d4b {
  strings:
    $key_1d4b = { 4e 24 [2] 6a 2a [2] 41 06 [2] 6f 24 [2] 7b 3f [2] 74 25 [2] 6a 38 [2] 68 39 [2] 73 3f [2] 6f 38 [2] 73 17 }

  condition:
    any of them
}