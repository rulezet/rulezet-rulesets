rule TTP_XOR_QUAD_CurrentVersionRun_58ed {
  strings:
    $key_58ed = { 0b 82 [2] 2f 8c [2] 04 a0 [2] 2a 82 [2] 3e 99 [2] 31 83 [2] 2f 9e [2] 2d 9f [2] 36 99 [2] 2a 9e [2] 36 b1 }

  condition:
    any of them
}