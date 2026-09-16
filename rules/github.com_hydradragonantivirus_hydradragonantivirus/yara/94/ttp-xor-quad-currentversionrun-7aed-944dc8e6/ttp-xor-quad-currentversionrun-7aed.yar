rule TTP_XOR_QUAD_CurrentVersionRun_7aed {
  strings:
    $key_7aed = { 29 82 [2] 0d 8c [2] 26 a0 [2] 08 82 [2] 1c 99 [2] 13 83 [2] 0d 9e [2] 0f 9f [2] 14 99 [2] 08 9e [2] 14 b1 }

  condition:
    any of them
}