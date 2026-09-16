rule TTP_XOR_QUAD_CurrentVersionRun_79ed {
  strings:
    $key_79ed = { 2a 82 [2] 0e 8c [2] 25 a0 [2] 0b 82 [2] 1f 99 [2] 10 83 [2] 0e 9e [2] 0c 9f [2] 17 99 [2] 0b 9e [2] 17 b1 }

  condition:
    any of them
}