rule TTP_XOR_QUAD_CurrentVersionRun_7d37 {
  strings:
    $key_7d37 = { 2e 58 [2] 0a 56 [2] 21 7a [2] 0f 58 [2] 1b 43 [2] 14 59 [2] 0a 44 [2] 08 45 [2] 13 43 [2] 0f 44 [2] 13 6b }

  condition:
    any of them
}