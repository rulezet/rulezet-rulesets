rule TTP_XOR_QUAD_CurrentVersionRun_f455 {
  strings:
    $key_f455 = { a7 3a [2] 83 34 [2] a8 18 [2] 86 3a [2] 92 21 [2] 9d 3b [2] 83 26 [2] 81 27 [2] 9a 21 [2] 86 26 [2] 9a 09 }

  condition:
    any of them
}