rule TTP_XOR_QUAD_CurrentVersionRun_67f8 {
  strings:
    $key_67f8 = { 34 97 [2] 10 99 [2] 3b b5 [2] 15 97 [2] 01 8c [2] 0e 96 [2] 10 8b [2] 12 8a [2] 09 8c [2] 15 8b [2] 09 a4 }

  condition:
    any of them
}