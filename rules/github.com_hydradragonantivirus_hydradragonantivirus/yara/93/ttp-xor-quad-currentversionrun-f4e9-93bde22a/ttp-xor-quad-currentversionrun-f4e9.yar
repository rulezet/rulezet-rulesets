rule TTP_XOR_QUAD_CurrentVersionRun_f4e9 {
  strings:
    $key_f4e9 = { a7 86 [2] 83 88 [2] a8 a4 [2] 86 86 [2] 92 9d [2] 9d 87 [2] 83 9a [2] 81 9b [2] 9a 9d [2] 86 9a [2] 9a b5 }

  condition:
    any of them
}