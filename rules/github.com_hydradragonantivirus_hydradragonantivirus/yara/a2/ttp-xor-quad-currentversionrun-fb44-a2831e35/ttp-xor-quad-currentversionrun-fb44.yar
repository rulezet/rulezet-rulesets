rule TTP_XOR_QUAD_CurrentVersionRun_fb44 {
  strings:
    $key_fb44 = { a8 2b [2] 8c 25 [2] a7 09 [2] 89 2b [2] 9d 30 [2] 92 2a [2] 8c 37 [2] 8e 36 [2] 95 30 [2] 89 37 [2] 95 18 }

  condition:
    any of them
}