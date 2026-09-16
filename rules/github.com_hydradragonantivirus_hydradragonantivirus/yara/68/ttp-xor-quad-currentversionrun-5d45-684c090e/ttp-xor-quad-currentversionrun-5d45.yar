rule TTP_XOR_QUAD_CurrentVersionRun_5d45 {
  strings:
    $key_5d45 = { 0e 2a [2] 2a 24 [2] 01 08 [2] 2f 2a [2] 3b 31 [2] 34 2b [2] 2a 36 [2] 28 37 [2] 33 31 [2] 2f 36 [2] 33 19 }

  condition:
    any of them
}