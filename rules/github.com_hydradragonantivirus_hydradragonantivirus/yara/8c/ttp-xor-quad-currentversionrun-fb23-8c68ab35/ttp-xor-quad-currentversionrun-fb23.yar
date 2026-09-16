rule TTP_XOR_QUAD_CurrentVersionRun_fb23 {
  strings:
    $key_fb23 = { a8 4c [2] 8c 42 [2] a7 6e [2] 89 4c [2] 9d 57 [2] 92 4d [2] 8c 50 [2] 8e 51 [2] 95 57 [2] 89 50 [2] 95 7f }

  condition:
    any of them
}