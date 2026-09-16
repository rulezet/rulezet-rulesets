rule TTP_XOR_QUAD_CurrentVersionRun_fa61 {
  strings:
    $key_fa61 = { a9 0e [2] 8d 00 [2] a6 2c [2] 88 0e [2] 9c 15 [2] 93 0f [2] 8d 12 [2] 8f 13 [2] 94 15 [2] 88 12 [2] 94 3d }

  condition:
    any of them
}