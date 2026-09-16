rule TTP_XOR_QUAD_CurrentVersionRun_4007 {
  strings:
    $key_4007 = { 13 68 [2] 37 66 [2] 1c 4a [2] 32 68 [2] 26 73 [2] 29 69 [2] 37 74 [2] 35 75 [2] 2e 73 [2] 32 74 [2] 2e 5b }

  condition:
    any of them
}