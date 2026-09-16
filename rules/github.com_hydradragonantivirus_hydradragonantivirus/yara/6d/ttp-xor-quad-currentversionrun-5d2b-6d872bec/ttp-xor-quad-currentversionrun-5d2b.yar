rule TTP_XOR_QUAD_CurrentVersionRun_5d2b {
  strings:
    $key_5d2b = { 0e 44 [2] 2a 4a [2] 01 66 [2] 2f 44 [2] 3b 5f [2] 34 45 [2] 2a 58 [2] 28 59 [2] 33 5f [2] 2f 58 [2] 33 77 }

  condition:
    any of them
}