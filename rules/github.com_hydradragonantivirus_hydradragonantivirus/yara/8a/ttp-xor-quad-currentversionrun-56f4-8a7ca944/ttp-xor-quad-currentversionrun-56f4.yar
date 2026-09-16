rule TTP_XOR_QUAD_CurrentVersionRun_56f4 {
  strings:
    $key_56f4 = { 05 9b [2] 21 95 [2] 0a b9 [2] 24 9b [2] 30 80 [2] 3f 9a [2] 21 87 [2] 23 86 [2] 38 80 [2] 24 87 [2] 38 a8 }

  condition:
    any of them
}