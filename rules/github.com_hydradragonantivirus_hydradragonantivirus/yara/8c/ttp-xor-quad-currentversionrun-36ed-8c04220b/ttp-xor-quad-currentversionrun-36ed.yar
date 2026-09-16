rule TTP_XOR_QUAD_CurrentVersionRun_36ed {
  strings:
    $key_36ed = { 65 82 [2] 41 8c [2] 6a a0 [2] 44 82 [2] 50 99 [2] 5f 83 [2] 41 9e [2] 43 9f [2] 58 99 [2] 44 9e [2] 58 b1 }

  condition:
    any of them
}