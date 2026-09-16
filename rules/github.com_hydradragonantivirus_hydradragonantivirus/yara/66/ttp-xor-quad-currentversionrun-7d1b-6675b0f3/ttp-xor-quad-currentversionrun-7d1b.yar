rule TTP_XOR_QUAD_CurrentVersionRun_7d1b {
  strings:
    $key_7d1b = { 2e 74 [2] 0a 7a [2] 21 56 [2] 0f 74 [2] 1b 6f [2] 14 75 [2] 0a 68 [2] 08 69 [2] 13 6f [2] 0f 68 [2] 13 47 }

  condition:
    any of them
}