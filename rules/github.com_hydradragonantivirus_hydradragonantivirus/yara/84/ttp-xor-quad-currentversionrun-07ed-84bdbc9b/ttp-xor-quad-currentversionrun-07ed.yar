rule TTP_XOR_QUAD_CurrentVersionRun_07ed {
  strings:
    $key_07ed = { 54 82 [2] 70 8c [2] 5b a0 [2] 75 82 [2] 61 99 [2] 6e 83 [2] 70 9e [2] 72 9f [2] 69 99 [2] 75 9e [2] 69 b1 }

  condition:
    any of them
}