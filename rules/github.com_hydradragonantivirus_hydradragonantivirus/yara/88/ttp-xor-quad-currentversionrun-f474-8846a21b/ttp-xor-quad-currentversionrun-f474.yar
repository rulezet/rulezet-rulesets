rule TTP_XOR_QUAD_CurrentVersionRun_f474 {
  strings:
    $key_f474 = { a7 1b [2] 83 15 [2] a8 39 [2] 86 1b [2] 92 00 [2] 9d 1a [2] 83 07 [2] 81 06 [2] 9a 00 [2] 86 07 [2] 9a 28 }

  condition:
    any of them
}