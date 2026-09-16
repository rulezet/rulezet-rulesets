rule TTP_XOR_QUAD_CurrentVersionRun_7d78 {
  strings:
    $key_7d78 = { 2e 17 [2] 0a 19 [2] 21 35 [2] 0f 17 [2] 1b 0c [2] 14 16 [2] 0a 0b [2] 08 0a [2] 13 0c [2] 0f 0b [2] 13 24 }

  condition:
    any of them
}