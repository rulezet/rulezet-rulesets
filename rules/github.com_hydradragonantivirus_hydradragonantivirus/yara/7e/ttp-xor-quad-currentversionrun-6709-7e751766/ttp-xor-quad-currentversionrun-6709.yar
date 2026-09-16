rule TTP_XOR_QUAD_CurrentVersionRun_6709 {
  strings:
    $key_6709 = { 34 66 [2] 10 68 [2] 3b 44 [2] 15 66 [2] 01 7d [2] 0e 67 [2] 10 7a [2] 12 7b [2] 09 7d [2] 15 7a [2] 09 55 }

  condition:
    any of them
}