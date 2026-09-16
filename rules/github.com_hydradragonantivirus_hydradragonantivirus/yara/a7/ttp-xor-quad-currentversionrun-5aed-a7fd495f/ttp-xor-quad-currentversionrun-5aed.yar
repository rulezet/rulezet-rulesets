rule TTP_XOR_QUAD_CurrentVersionRun_5aed {
  strings:
    $key_5aed = { 09 82 [2] 2d 8c [2] 06 a0 [2] 28 82 [2] 3c 99 [2] 33 83 [2] 2d 9e [2] 2f 9f [2] 34 99 [2] 28 9e [2] 34 b1 }

  condition:
    any of them
}