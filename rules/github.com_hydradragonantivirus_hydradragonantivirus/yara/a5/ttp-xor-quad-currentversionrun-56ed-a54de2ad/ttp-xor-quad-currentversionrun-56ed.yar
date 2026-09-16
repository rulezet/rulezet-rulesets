rule TTP_XOR_QUAD_CurrentVersionRun_56ed {
  strings:
    $key_56ed = { 05 82 [2] 21 8c [2] 0a a0 [2] 24 82 [2] 30 99 [2] 3f 83 [2] 21 9e [2] 23 9f [2] 38 99 [2] 24 9e [2] 38 b1 }

  condition:
    any of them
}