rule TTP_XOR_QUAD_CurrentVersionRun_6744 {
  strings:
    $key_6744 = { 34 2b [2] 10 25 [2] 3b 09 [2] 15 2b [2] 01 30 [2] 0e 2a [2] 10 37 [2] 12 36 [2] 09 30 [2] 15 37 [2] 09 18 }

  condition:
    any of them
}