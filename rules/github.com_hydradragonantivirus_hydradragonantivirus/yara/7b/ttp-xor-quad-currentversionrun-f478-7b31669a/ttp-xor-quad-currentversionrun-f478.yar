rule TTP_XOR_QUAD_CurrentVersionRun_f478 {
  strings:
    $key_f478 = { a7 17 [2] 83 19 [2] a8 35 [2] 86 17 [2] 92 0c [2] 9d 16 [2] 83 0b [2] 81 0a [2] 9a 0c [2] 86 0b [2] 9a 24 }

  condition:
    any of them
}