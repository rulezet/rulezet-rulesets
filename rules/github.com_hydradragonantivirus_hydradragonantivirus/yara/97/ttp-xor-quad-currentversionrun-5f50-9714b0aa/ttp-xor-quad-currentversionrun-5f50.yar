rule TTP_XOR_QUAD_CurrentVersionRun_5f50 {
  strings:
    $key_5f50 = { 0c 3f [2] 28 31 [2] 03 1d [2] 2d 3f [2] 39 24 [2] 36 3e [2] 28 23 [2] 2a 22 [2] 31 24 [2] 2d 23 [2] 31 0c }

  condition:
    any of them
}