rule TTP_XOR_QUAD_CurrentVersionRun_fb4b {
  strings:
    $key_fb4b = { a8 24 [2] 8c 2a [2] a7 06 [2] 89 24 [2] 9d 3f [2] 92 25 [2] 8c 38 [2] 8e 39 [2] 95 3f [2] 89 38 [2] 95 17 }

  condition:
    any of them
}