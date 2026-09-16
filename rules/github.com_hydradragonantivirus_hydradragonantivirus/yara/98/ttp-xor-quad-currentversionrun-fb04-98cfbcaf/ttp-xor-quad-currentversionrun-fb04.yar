rule TTP_XOR_QUAD_CurrentVersionRun_fb04 {
  strings:
    $key_fb04 = { a8 6b [2] 8c 65 [2] a7 49 [2] 89 6b [2] 9d 70 [2] 92 6a [2] 8c 77 [2] 8e 76 [2] 95 70 [2] 89 77 [2] 95 58 }

  condition:
    any of them
}