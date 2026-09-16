rule TTP_XOR_QUAD_CurrentVersionRun_f459 {
  strings:
    $key_f459 = { a7 36 [2] 83 38 [2] a8 14 [2] 86 36 [2] 92 2d [2] 9d 37 [2] 83 2a [2] 81 2b [2] 9a 2d [2] 86 2a [2] 9a 05 }

  condition:
    any of them
}