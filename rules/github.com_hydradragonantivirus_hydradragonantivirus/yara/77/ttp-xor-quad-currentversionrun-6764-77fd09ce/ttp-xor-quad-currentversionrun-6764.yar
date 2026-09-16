rule TTP_XOR_QUAD_CurrentVersionRun_6764 {
  strings:
    $key_6764 = { 34 0b [2] 10 05 [2] 3b 29 [2] 15 0b [2] 01 10 [2] 0e 0a [2] 10 17 [2] 12 16 [2] 09 10 [2] 15 17 [2] 09 38 }

  condition:
    any of them
}