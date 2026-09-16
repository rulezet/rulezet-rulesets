rule TTP_XOR_QUAD_CurrentVersionRun_fb6d {
  strings:
    $key_fb6d = { a8 02 [2] 8c 0c [2] a7 20 [2] 89 02 [2] 9d 19 [2] 92 03 [2] 8c 1e [2] 8e 1f [2] 95 19 [2] 89 1e [2] 95 31 }

  condition:
    any of them
}