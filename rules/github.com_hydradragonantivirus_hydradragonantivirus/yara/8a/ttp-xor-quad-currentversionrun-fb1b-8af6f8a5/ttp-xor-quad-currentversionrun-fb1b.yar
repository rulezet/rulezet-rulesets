rule TTP_XOR_QUAD_CurrentVersionRun_fb1b {
  strings:
    $key_fb1b = { a8 74 [2] 8c 7a [2] a7 56 [2] 89 74 [2] 9d 6f [2] 92 75 [2] 8c 68 [2] 8e 69 [2] 95 6f [2] 89 68 [2] 95 47 }

  condition:
    any of them
}