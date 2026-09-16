rule TTP_XOR_QUAD_CurrentVersionRun_5d75 {
  strings:
    $key_5d75 = { 0e 1a [2] 2a 14 [2] 01 38 [2] 2f 1a [2] 3b 01 [2] 34 1b [2] 2a 06 [2] 28 07 [2] 33 01 [2] 2f 06 [2] 33 29 }

  condition:
    any of them
}