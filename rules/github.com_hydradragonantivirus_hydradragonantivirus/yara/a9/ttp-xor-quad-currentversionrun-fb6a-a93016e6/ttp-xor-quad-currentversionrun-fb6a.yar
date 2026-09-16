rule TTP_XOR_QUAD_CurrentVersionRun_fb6a {
  strings:
    $key_fb6a = { a8 05 [2] 8c 0b [2] a7 27 [2] 89 05 [2] 9d 1e [2] 92 04 [2] 8c 19 [2] 8e 18 [2] 95 1e [2] 89 19 [2] 95 36 }

  condition:
    any of them
}