rule TTP_XOR_QUAD_CurrentVersionRun_f468 {
  strings:
    $key_f468 = { a7 07 [2] 83 09 [2] a8 25 [2] 86 07 [2] 92 1c [2] 9d 06 [2] 83 1b [2] 81 1a [2] 9a 1c [2] 86 1b [2] 9a 34 }

  condition:
    any of them
}