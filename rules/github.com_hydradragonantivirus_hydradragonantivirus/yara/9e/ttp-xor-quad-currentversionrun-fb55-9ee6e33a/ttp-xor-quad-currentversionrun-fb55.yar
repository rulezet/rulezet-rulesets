rule TTP_XOR_QUAD_CurrentVersionRun_fb55 {
  strings:
    $key_fb55 = { a8 3a [2] 8c 34 [2] a7 18 [2] 89 3a [2] 9d 21 [2] 92 3b [2] 8c 26 [2] 8e 27 [2] 95 21 [2] 89 26 [2] 95 09 }

  condition:
    any of them
}