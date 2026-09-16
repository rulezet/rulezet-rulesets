rule TTP_XOR_QUAD_CurrentVersionRun_fb45 {
  strings:
    $key_fb45 = { a8 2a [2] 8c 24 [2] a7 08 [2] 89 2a [2] 9d 31 [2] 92 2b [2] 8c 36 [2] 8e 37 [2] 95 31 [2] 89 36 [2] 95 19 }

  condition:
    any of them
}