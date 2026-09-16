rule TTP_XOR_QUAD_CurrentVersionRun_fb77 {
  strings:
    $key_fb77 = { a8 18 [2] 8c 16 [2] a7 3a [2] 89 18 [2] 9d 03 [2] 92 19 [2] 8c 04 [2] 8e 05 [2] 95 03 [2] 89 04 [2] 95 2b }

  condition:
    any of them
}