rule TTP_XOR_QUAD_CurrentVersionRun_6779 {
  strings:
    $key_6779 = { 34 16 [2] 10 18 [2] 3b 34 [2] 15 16 [2] 01 0d [2] 0e 17 [2] 10 0a [2] 12 0b [2] 09 0d [2] 15 0a [2] 09 25 }

  condition:
    any of them
}