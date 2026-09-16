rule TTP_XOR_QUAD_CurrentVersionRun_5d78 {
  strings:
    $key_5d78 = { 0e 17 [2] 2a 19 [2] 01 35 [2] 2f 17 [2] 3b 0c [2] 34 16 [2] 2a 0b [2] 28 0a [2] 33 0c [2] 2f 0b [2] 33 24 }

  condition:
    any of them
}