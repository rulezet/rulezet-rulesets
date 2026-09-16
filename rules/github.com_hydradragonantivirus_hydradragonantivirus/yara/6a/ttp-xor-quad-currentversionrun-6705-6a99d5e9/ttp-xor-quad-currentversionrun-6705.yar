rule TTP_XOR_QUAD_CurrentVersionRun_6705 {
  strings:
    $key_6705 = { 34 6a [2] 10 64 [2] 3b 48 [2] 15 6a [2] 01 71 [2] 0e 6b [2] 10 76 [2] 12 77 [2] 09 71 [2] 15 76 [2] 09 59 }

  condition:
    any of them
}