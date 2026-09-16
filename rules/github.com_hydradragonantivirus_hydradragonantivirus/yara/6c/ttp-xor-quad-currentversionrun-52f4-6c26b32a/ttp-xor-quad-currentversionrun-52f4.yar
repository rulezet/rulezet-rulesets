rule TTP_XOR_QUAD_CurrentVersionRun_52f4 {
  strings:
    $key_52f4 = { 01 9b [2] 25 95 [2] 0e b9 [2] 20 9b [2] 34 80 [2] 3b 9a [2] 25 87 [2] 27 86 [2] 3c 80 [2] 20 87 [2] 3c a8 }

  condition:
    any of them
}