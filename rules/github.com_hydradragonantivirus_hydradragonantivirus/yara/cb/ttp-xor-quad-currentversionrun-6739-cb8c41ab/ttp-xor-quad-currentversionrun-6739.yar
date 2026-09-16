rule TTP_XOR_QUAD_CurrentVersionRun_6739 {
  strings:
    $key_6739 = { 34 56 [2] 10 58 [2] 3b 74 [2] 15 56 [2] 01 4d [2] 0e 57 [2] 10 4a [2] 12 4b [2] 09 4d [2] 15 4a [2] 09 65 }

  condition:
    any of them
}