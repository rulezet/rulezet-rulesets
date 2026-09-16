rule TTP_XOR_QUAD_CurrentVersionRun_fb0d {
  strings:
    $key_fb0d = { a8 62 [2] 8c 6c [2] a7 40 [2] 89 62 [2] 9d 79 [2] 92 63 [2] 8c 7e [2] 8e 7f [2] 95 79 [2] 89 7e [2] 95 51 }

  condition:
    any of them
}