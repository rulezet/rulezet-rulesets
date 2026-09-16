rule TTP_XOR_QUAD_CurrentVersionRun_7d06 {
  strings:
    $key_7d06 = { 2e 69 [2] 0a 67 [2] 21 4b [2] 0f 69 [2] 1b 72 [2] 14 68 [2] 0a 75 [2] 08 74 [2] 13 72 [2] 0f 75 [2] 13 5a }

  condition:
    any of them
}