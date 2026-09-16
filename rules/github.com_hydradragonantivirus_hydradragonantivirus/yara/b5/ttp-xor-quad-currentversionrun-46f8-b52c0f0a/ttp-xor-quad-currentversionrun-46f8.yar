rule TTP_XOR_QUAD_CurrentVersionRun_46f8 {
  strings:
    $key_46f8 = { 15 97 [2] 31 99 [2] 1a b5 [2] 34 97 [2] 20 8c [2] 2f 96 [2] 31 8b [2] 33 8a [2] 28 8c [2] 34 8b [2] 28 a4 }

  condition:
    any of them
}