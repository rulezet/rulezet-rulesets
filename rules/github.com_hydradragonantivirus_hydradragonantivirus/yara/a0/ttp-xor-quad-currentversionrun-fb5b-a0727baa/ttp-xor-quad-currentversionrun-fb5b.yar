rule TTP_XOR_QUAD_CurrentVersionRun_fb5b {
  strings:
    $key_fb5b = { a8 34 [2] 8c 3a [2] a7 16 [2] 89 34 [2] 9d 2f [2] 92 35 [2] 8c 28 [2] 8e 29 [2] 95 2f [2] 89 28 [2] 95 07 }

  condition:
    any of them
}