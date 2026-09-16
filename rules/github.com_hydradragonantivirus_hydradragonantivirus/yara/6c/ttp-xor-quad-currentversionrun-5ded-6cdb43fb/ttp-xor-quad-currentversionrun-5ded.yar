rule TTP_XOR_QUAD_CurrentVersionRun_5ded {
  strings:
    $key_5ded = { 0e 82 [2] 2a 8c [2] 01 a0 [2] 2f 82 [2] 3b 99 [2] 34 83 [2] 2a 9e [2] 28 9f [2] 33 99 [2] 2f 9e [2] 33 b1 }

  condition:
    any of them
}