rule TTP_XOR_QUAD_CurrentVersionRun_fb75 {
  strings:
    $key_fb75 = { a8 1a [2] 8c 14 [2] a7 38 [2] 89 1a [2] 9d 01 [2] 92 1b [2] 8c 06 [2] 8e 07 [2] 95 01 [2] 89 06 [2] 95 29 }

  condition:
    any of them
}