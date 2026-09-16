rule TTP_XOR_QUAD_CurrentVersionRun_7d47 {
  strings:
    $key_7d47 = { 2e 28 [2] 0a 26 [2] 21 0a [2] 0f 28 [2] 1b 33 [2] 14 29 [2] 0a 34 [2] 08 35 [2] 13 33 [2] 0f 34 [2] 13 1b }

  condition:
    any of them
}