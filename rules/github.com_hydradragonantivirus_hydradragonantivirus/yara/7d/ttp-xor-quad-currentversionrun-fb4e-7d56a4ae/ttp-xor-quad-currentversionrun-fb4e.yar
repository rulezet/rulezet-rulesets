rule TTP_XOR_QUAD_CurrentVersionRun_fb4e {
  strings:
    $key_fb4e = { a8 21 [2] 8c 2f [2] a7 03 [2] 89 21 [2] 9d 3a [2] 92 20 [2] 8c 3d [2] 8e 3c [2] 95 3a [2] 89 3d [2] 95 12 }

  condition:
    any of them
}