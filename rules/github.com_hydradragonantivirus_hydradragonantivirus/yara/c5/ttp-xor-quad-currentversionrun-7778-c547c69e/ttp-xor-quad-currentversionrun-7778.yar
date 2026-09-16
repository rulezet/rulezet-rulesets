rule TTP_XOR_QUAD_CurrentVersionRun_7778 {
  strings:
    $key_7778 = { 24 17 [2] 00 19 [2] 2b 35 [2] 05 17 [2] 11 0c [2] 1e 16 [2] 00 0b [2] 02 0a [2] 19 0c [2] 05 0b [2] 19 24 }

  condition:
    any of them
}