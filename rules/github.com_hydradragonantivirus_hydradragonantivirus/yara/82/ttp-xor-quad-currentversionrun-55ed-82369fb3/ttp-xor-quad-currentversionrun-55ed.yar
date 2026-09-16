rule TTP_XOR_QUAD_CurrentVersionRun_55ed {
  strings:
    $key_55ed = { 06 82 [2] 22 8c [2] 09 a0 [2] 27 82 [2] 33 99 [2] 3c 83 [2] 22 9e [2] 20 9f [2] 3b 99 [2] 27 9e [2] 3b b1 }

  condition:
    any of them
}