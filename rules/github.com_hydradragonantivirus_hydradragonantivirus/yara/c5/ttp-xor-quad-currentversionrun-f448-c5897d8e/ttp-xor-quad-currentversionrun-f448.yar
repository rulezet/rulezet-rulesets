rule TTP_XOR_QUAD_CurrentVersionRun_f448 {
  strings:
    $key_f448 = { a7 27 [2] 83 29 [2] a8 05 [2] 86 27 [2] 92 3c [2] 9d 26 [2] 83 3b [2] 81 3a [2] 9a 3c [2] 86 3b [2] 9a 14 }

  condition:
    any of them
}