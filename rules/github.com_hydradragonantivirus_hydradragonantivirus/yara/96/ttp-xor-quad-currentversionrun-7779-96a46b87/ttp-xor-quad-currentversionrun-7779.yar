rule TTP_XOR_QUAD_CurrentVersionRun_7779 {
  strings:
    $key_7779 = { 24 16 [2] 00 18 [2] 2b 34 [2] 05 16 [2] 11 0d [2] 1e 17 [2] 00 0a [2] 02 0b [2] 19 0d [2] 05 0a [2] 19 25 }

  condition:
    any of them
}