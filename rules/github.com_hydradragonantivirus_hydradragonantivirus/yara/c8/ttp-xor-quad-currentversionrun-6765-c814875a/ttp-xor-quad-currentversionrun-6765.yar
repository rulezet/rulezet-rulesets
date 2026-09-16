rule TTP_XOR_QUAD_CurrentVersionRun_6765 {
  strings:
    $key_6765 = { 34 0a [2] 10 04 [2] 3b 28 [2] 15 0a [2] 01 11 [2] 0e 0b [2] 10 16 [2] 12 17 [2] 09 11 [2] 15 16 [2] 09 39 }

  condition:
    any of them
}