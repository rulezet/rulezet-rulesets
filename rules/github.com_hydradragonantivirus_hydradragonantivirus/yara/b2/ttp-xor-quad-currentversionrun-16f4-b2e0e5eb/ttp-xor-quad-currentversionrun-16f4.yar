rule TTP_XOR_QUAD_CurrentVersionRun_16f4 {
  strings:
    $key_16f4 = { 45 9b [2] 61 95 [2] 4a b9 [2] 64 9b [2] 70 80 [2] 7f 9a [2] 61 87 [2] 63 86 [2] 78 80 [2] 64 87 [2] 78 a8 }

  condition:
    any of them
}