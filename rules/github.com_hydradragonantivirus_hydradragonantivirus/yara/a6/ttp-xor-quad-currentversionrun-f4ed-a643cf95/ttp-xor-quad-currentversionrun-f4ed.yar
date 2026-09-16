rule TTP_XOR_QUAD_CurrentVersionRun_f4ed {
  strings:
    $key_f4ed = { a7 82 [2] 83 8c [2] a8 a0 [2] 86 82 [2] 92 99 [2] 9d 83 [2] 83 9e [2] 81 9f [2] 9a 99 [2] 86 9e [2] 9a b1 }

  condition:
    any of them
}