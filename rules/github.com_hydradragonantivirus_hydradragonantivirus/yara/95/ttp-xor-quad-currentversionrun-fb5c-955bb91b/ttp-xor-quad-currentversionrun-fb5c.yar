rule TTP_XOR_QUAD_CurrentVersionRun_fb5c {
  strings:
    $key_fb5c = { a8 33 [2] 8c 3d [2] a7 11 [2] 89 33 [2] 9d 28 [2] 92 32 [2] 8c 2f [2] 8e 2e [2] 95 28 [2] 89 2f [2] 95 00 }

  condition:
    any of them
}