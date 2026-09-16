rule TTP_XOR_QUAD_CurrentVersionRun_fb2b {
  strings:
    $key_fb2b = { a8 44 [2] 8c 4a [2] a7 66 [2] 89 44 [2] 9d 5f [2] 92 45 [2] 8c 58 [2] 8e 59 [2] 95 5f [2] 89 58 [2] 95 77 }

  condition:
    any of them
}