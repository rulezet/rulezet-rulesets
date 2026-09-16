rule TTP_XOR_QUAD_CurrentVersionRun_fb0a {
  strings:
    $key_fb0a = { a8 65 [2] 8c 6b [2] a7 47 [2] 89 65 [2] 9d 7e [2] 92 64 [2] 8c 79 [2] 8e 78 [2] 95 7e [2] 89 79 [2] 95 56 }

  condition:
    any of them
}