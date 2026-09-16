rule TTP_XOR_QUAD_CurrentVersionRun_fb4f {
  strings:
    $key_fb4f = { a8 20 [2] 8c 2e [2] a7 02 [2] 89 20 [2] 9d 3b [2] 92 21 [2] 8c 3c [2] 8e 3d [2] 95 3b [2] 89 3c [2] 95 13 }

  condition:
    any of them
}