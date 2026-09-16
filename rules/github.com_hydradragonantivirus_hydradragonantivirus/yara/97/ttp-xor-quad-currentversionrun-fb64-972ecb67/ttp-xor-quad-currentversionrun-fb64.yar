rule TTP_XOR_QUAD_CurrentVersionRun_fb64 {
  strings:
    $key_fb64 = { a8 0b [2] 8c 05 [2] a7 29 [2] 89 0b [2] 9d 10 [2] 92 0a [2] 8c 17 [2] 8e 16 [2] 95 10 [2] 89 17 [2] 95 38 }

  condition:
    any of them
}