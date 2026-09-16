rule TTP_XOR_QUAD_CurrentVersionRun_f444 {
  strings:
    $key_f444 = { a7 2b [2] 83 25 [2] a8 09 [2] 86 2b [2] 92 30 [2] 9d 2a [2] 83 37 [2] 81 36 [2] 9a 30 [2] 86 37 [2] 9a 18 }

  condition:
    any of them
}