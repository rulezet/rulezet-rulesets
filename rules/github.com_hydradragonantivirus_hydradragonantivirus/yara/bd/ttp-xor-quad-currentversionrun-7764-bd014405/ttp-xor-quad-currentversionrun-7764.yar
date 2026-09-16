rule TTP_XOR_QUAD_CurrentVersionRun_7764 {
  strings:
    $key_7764 = { 24 0b [2] 00 05 [2] 2b 29 [2] 05 0b [2] 11 10 [2] 1e 0a [2] 00 17 [2] 02 16 [2] 19 10 [2] 05 17 [2] 19 38 }

  condition:
    any of them
}