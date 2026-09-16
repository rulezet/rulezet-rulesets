rule TTP_XOR_QUAD_CurrentVersionRun_f561 {
  strings:
    $key_f561 = { a6 0e [2] 82 00 [2] a9 2c [2] 87 0e [2] 93 15 [2] 9c 0f [2] 82 12 [2] 80 13 [2] 9b 15 [2] 87 12 [2] 9b 3d }

  condition:
    any of them
}