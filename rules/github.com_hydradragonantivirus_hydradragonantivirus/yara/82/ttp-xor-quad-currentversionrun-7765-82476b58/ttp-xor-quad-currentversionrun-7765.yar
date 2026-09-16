rule TTP_XOR_QUAD_CurrentVersionRun_7765 {
  strings:
    $key_7765 = { 24 0a [2] 00 04 [2] 2b 28 [2] 05 0a [2] 11 11 [2] 1e 0b [2] 00 16 [2] 02 17 [2] 19 11 [2] 05 16 [2] 19 39 }

  condition:
    any of them
}