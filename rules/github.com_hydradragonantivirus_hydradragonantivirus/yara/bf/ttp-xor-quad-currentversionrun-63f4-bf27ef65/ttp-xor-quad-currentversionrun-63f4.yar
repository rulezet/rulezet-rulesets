rule TTP_XOR_QUAD_CurrentVersionRun_63f4 {
  strings:
    $key_63f4 = { 30 9b [2] 14 95 [2] 3f b9 [2] 11 9b [2] 05 80 [2] 0a 9a [2] 14 87 [2] 16 86 [2] 0d 80 [2] 11 87 [2] 0d a8 }

  condition:
    any of them
}