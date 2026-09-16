rule TTP_XOR_QUAD_CurrentVersionRun_7d07 {
  strings:
    $key_7d07 = { 2e 68 [2] 0a 66 [2] 21 4a [2] 0f 68 [2] 1b 73 [2] 14 69 [2] 0a 74 [2] 08 75 [2] 13 73 [2] 0f 74 [2] 13 5b }

  condition:
    any of them
}