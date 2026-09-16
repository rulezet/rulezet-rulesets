rule TTP_XOR_QUAD_CurrentVersionRun_fb03 {
  strings:
    $key_fb03 = { a8 6c [2] 8c 62 [2] a7 4e [2] 89 6c [2] 9d 77 [2] 92 6d [2] 8c 70 [2] 8e 71 [2] 95 77 [2] 89 70 [2] 95 5f }

  condition:
    any of them
}