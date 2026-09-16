rule TTP_XOR_QUAD_CurrentVersionRun_64ed {
  strings:
    $key_64ed = { 37 82 [2] 13 8c [2] 38 a0 [2] 16 82 [2] 02 99 [2] 0d 83 [2] 13 9e [2] 11 9f [2] 0a 99 [2] 16 9e [2] 0a b1 }

  condition:
    any of them
}