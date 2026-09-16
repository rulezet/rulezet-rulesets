rule TTP_XOR_QUAD_CurrentVersionRun_f458 {
  strings:
    $key_f458 = { a7 37 [2] 83 39 [2] a8 15 [2] 86 37 [2] 92 2c [2] 9d 36 [2] 83 2b [2] 81 2a [2] 9a 2c [2] 86 2b [2] 9a 04 }

  condition:
    any of them
}