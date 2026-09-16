rule TTP_XOR_QUAD_CurrentVersionRun_fb31 {
  strings:
    $key_fb31 = { a8 5e [2] 8c 50 [2] a7 7c [2] 89 5e [2] 9d 45 [2] 92 5f [2] 8c 42 [2] 8e 43 [2] 95 45 [2] 89 42 [2] 95 6d }

  condition:
    any of them
}