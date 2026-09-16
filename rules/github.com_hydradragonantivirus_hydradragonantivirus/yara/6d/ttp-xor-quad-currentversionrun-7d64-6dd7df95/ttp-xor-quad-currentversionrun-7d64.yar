rule TTP_XOR_QUAD_CurrentVersionRun_7d64 {
  strings:
    $key_7d64 = { 2e 0b [2] 0a 05 [2] 21 29 [2] 0f 0b [2] 1b 10 [2] 14 0a [2] 0a 17 [2] 08 16 [2] 13 10 [2] 0f 17 [2] 13 38 }

  condition:
    any of them
}