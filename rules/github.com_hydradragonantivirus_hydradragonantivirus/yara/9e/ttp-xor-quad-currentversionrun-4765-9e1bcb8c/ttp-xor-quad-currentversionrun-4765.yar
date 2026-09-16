rule TTP_XOR_QUAD_CurrentVersionRun_4765 {
  strings:
    $key_4765 = { 14 0a [2] 30 04 [2] 1b 28 [2] 35 0a [2] 21 11 [2] 2e 0b [2] 30 16 [2] 32 17 [2] 29 11 [2] 35 16 [2] 29 39 }

  condition:
    any of them
}