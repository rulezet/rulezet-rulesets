rule TTP_XOR_QUAD_CurrentVersionRun_5d19 {
  strings:
    $key_5d19 = { 0e 76 [2] 2a 78 [2] 01 54 [2] 2f 76 [2] 3b 6d [2] 34 77 [2] 2a 6a [2] 28 6b [2] 33 6d [2] 2f 6a [2] 33 45 }

  condition:
    any of them
}