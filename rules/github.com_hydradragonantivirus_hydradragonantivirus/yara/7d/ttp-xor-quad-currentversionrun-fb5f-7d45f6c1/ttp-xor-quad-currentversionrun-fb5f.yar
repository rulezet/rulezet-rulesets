rule TTP_XOR_QUAD_CurrentVersionRun_fb5f {
  strings:
    $key_fb5f = { a8 30 [2] 8c 3e [2] a7 12 [2] 89 30 [2] 9d 2b [2] 92 31 [2] 8c 2c [2] 8e 2d [2] 95 2b [2] 89 2c [2] 95 03 }

  condition:
    any of them
}