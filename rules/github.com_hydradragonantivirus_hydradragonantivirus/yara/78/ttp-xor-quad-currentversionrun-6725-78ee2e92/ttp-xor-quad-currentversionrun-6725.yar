rule TTP_XOR_QUAD_CurrentVersionRun_6725 {
  strings:
    $key_6725 = { 34 4a [2] 10 44 [2] 3b 68 [2] 15 4a [2] 01 51 [2] 0e 4b [2] 10 56 [2] 12 57 [2] 09 51 [2] 15 56 [2] 09 79 }

  condition:
    any of them
}