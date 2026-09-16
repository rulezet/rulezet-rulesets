rule TTP_XOR_QUAD_CurrentVersionRun_46e9 {
  strings:
    $key_46e9 = { 15 86 [2] 31 88 [2] 1a a4 [2] 34 86 [2] 20 9d [2] 2f 87 [2] 31 9a [2] 33 9b [2] 28 9d [2] 34 9a [2] 28 b5 }

  condition:
    any of them
}