rule TTP_XOR_QUAD_CurrentVersionRun_68ed {
  strings:
    $key_68ed = { 3b 82 [2] 1f 8c [2] 34 a0 [2] 1a 82 [2] 0e 99 [2] 01 83 [2] 1f 9e [2] 1d 9f [2] 06 99 [2] 1a 9e [2] 06 b1 }

  condition:
    any of them
}