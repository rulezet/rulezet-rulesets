rule TTP_XOR_QUAD_CurrentVersionRun_67e9 {
  strings:
    $key_67e9 = { 34 86 [2] 10 88 [2] 3b a4 [2] 15 86 [2] 01 9d [2] 0e 87 [2] 10 9a [2] 12 9b [2] 09 9d [2] 15 9a [2] 09 b5 }

  condition:
    any of them
}