rule TTP_XOR_QUAD_CurrentVersionRun_11f4 {
  strings:
    $key_11f4 = { 42 9b [2] 66 95 [2] 4d b9 [2] 63 9b [2] 77 80 [2] 78 9a [2] 66 87 [2] 64 86 [2] 7f 80 [2] 63 87 [2] 7f a8 }

  condition:
    any of them
}