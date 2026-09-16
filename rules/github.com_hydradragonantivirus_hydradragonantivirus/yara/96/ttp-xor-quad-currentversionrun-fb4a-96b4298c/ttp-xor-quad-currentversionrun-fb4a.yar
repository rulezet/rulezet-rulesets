rule TTP_XOR_QUAD_CurrentVersionRun_fb4a {
  strings:
    $key_fb4a = { a8 25 [2] 8c 2b [2] a7 07 [2] 89 25 [2] 9d 3e [2] 92 24 [2] 8c 39 [2] 8e 38 [2] 95 3e [2] 89 39 [2] 95 16 }

  condition:
    any of them
}