rule TTP_XOR_QUAD_CurrentVersionRun_fb6b {
  strings:
    $key_fb6b = { a8 04 [2] 8c 0a [2] a7 26 [2] 89 04 [2] 9d 1f [2] 92 05 [2] 8c 18 [2] 8e 19 [2] 95 1f [2] 89 18 [2] 95 37 }

  condition:
    any of them
}