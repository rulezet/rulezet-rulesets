rule TTP_XOR_QUAD_CurrentVersionRun_fb6f {
  strings:
    $key_fb6f = { a8 00 [2] 8c 0e [2] a7 22 [2] 89 00 [2] 9d 1b [2] 92 01 [2] 8c 1c [2] 8e 1d [2] 95 1b [2] 89 1c [2] 95 33 }

  condition:
    any of them
}