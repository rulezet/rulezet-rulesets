rule TTP_XOR_QUAD_CurrentVersionRun_fb5e {
  strings:
    $key_fb5e = { a8 31 [2] 8c 3f [2] a7 13 [2] 89 31 [2] 9d 2a [2] 92 30 [2] 8c 2d [2] 8e 2c [2] 95 2a [2] 89 2d [2] 95 02 }

  condition:
    any of them
}