rule TTP_XOR_QUAD_CurrentVersionRun_fb66 {
  strings:
    $key_fb66 = { a8 09 [2] 8c 07 [2] a7 2b [2] 89 09 [2] 9d 12 [2] 92 08 [2] 8c 15 [2] 8e 14 [2] 95 12 [2] 89 15 [2] 95 3a }

  condition:
    any of them
}