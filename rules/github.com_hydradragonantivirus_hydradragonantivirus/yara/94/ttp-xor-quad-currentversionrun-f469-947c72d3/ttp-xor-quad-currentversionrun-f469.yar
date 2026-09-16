rule TTP_XOR_QUAD_CurrentVersionRun_f469 {
  strings:
    $key_f469 = { a7 06 [2] 83 08 [2] a8 24 [2] 86 06 [2] 92 1d [2] 9d 07 [2] 83 1a [2] 81 1b [2] 9a 1d [2] 86 1a [2] 9a 35 }

  condition:
    any of them
}