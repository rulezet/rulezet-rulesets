rule TTP_XOR_QUAD_CurrentVersionRun_fb01 {
  strings:
    $key_fb01 = { a8 6e [2] 8c 60 [2] a7 4c [2] 89 6e [2] 9d 75 [2] 92 6f [2] 8c 72 [2] 8e 73 [2] 95 75 [2] 89 72 [2] 95 5d }

  condition:
    any of them
}