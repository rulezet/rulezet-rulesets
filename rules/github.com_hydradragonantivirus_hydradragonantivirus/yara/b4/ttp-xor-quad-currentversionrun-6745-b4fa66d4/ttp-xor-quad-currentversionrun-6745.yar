rule TTP_XOR_QUAD_CurrentVersionRun_6745 {
  strings:
    $key_6745 = { 34 2a [2] 10 24 [2] 3b 08 [2] 15 2a [2] 01 31 [2] 0e 2b [2] 10 36 [2] 12 37 [2] 09 31 [2] 15 36 [2] 09 19 }

  condition:
    any of them
}