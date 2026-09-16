rule TTP_XOR_QUAD_CurrentVersionRun_fb7f {
  strings:
    $key_fb7f = { a8 10 [2] 8c 1e [2] a7 32 [2] 89 10 [2] 9d 0b [2] 92 11 [2] 8c 0c [2] 8e 0d [2] 95 0b [2] 89 0c [2] 95 23 }

  condition:
    any of them
}