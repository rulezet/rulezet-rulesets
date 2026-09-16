rule TTP_XOR_QUAD_CurrentVersionRun_fb7c {
  strings:
    $key_fb7c = { a8 13 [2] 8c 1d [2] a7 31 [2] 89 13 [2] 9d 08 [2] 92 12 [2] 8c 0f [2] 8e 0e [2] 95 08 [2] 89 0f [2] 95 20 }

  condition:
    any of them
}