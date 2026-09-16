rule TTP_XOR_QUAD_CurrentVersionRun_4778 {
  strings:
    $key_4778 = { 14 17 [2] 30 19 [2] 1b 35 [2] 35 17 [2] 21 0c [2] 2e 16 [2] 30 0b [2] 32 0a [2] 29 0c [2] 35 0b [2] 29 24 }

  condition:
    any of them
}