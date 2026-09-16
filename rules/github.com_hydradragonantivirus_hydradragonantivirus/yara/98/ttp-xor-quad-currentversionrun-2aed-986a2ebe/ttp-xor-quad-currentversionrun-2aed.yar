rule TTP_XOR_QUAD_CurrentVersionRun_2aed {
  strings:
    $key_2aed = { 79 82 [2] 5d 8c [2] 76 a0 [2] 58 82 [2] 4c 99 [2] 43 83 [2] 5d 9e [2] 5f 9f [2] 44 99 [2] 58 9e [2] 44 b1 }

  condition:
    any of them
}