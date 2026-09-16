rule TTP_XOR_QUAD_CurrentVersionRun_fb5a {
  strings:
    $key_fb5a = { a8 35 [2] 8c 3b [2] a7 17 [2] 89 35 [2] 9d 2e [2] 92 34 [2] 8c 29 [2] 8e 28 [2] 95 2e [2] 89 29 [2] 95 06 }

  condition:
    any of them
}