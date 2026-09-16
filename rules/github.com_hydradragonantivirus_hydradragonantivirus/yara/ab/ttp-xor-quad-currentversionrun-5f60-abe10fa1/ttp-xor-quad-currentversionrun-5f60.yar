rule TTP_XOR_QUAD_CurrentVersionRun_5f60 {
  strings:
    $key_5f60 = { 0c 0f [2] 28 01 [2] 03 2d [2] 2d 0f [2] 39 14 [2] 36 0e [2] 28 13 [2] 2a 12 [2] 31 14 [2] 2d 13 [2] 31 3c }

  condition:
    any of them
}