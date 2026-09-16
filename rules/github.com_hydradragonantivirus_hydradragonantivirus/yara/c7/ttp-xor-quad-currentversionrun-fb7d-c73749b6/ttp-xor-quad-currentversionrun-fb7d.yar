rule TTP_XOR_QUAD_CurrentVersionRun_fb7d {
  strings:
    $key_fb7d = { a8 12 [2] 8c 1c [2] a7 30 [2] 89 12 [2] 9d 09 [2] 92 13 [2] 8c 0e [2] 8e 0f [2] 95 09 [2] 89 0e [2] 95 21 }

  condition:
    any of them
}