rule TTP_XOR_QUAD_CurrentVersionRun_fb51 {
  strings:
    $key_fb51 = { a8 3e [2] 8c 30 [2] a7 1c [2] 89 3e [2] 9d 25 [2] 92 3f [2] 8c 22 [2] 8e 23 [2] 95 25 [2] 89 22 [2] 95 0d }

  condition:
    any of them
}