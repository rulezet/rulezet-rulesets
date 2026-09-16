rule TTP_XOR_QUAD_CurrentVersionRun_36f4 {
  strings:
    $key_36f4 = { 65 9b [2] 41 95 [2] 6a b9 [2] 44 9b [2] 50 80 [2] 5f 9a [2] 41 87 [2] 43 86 [2] 58 80 [2] 44 87 [2] 58 a8 }

  condition:
    any of them
}