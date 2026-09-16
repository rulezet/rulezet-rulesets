rule TTP_XOR_QUAD_CurrentVersionRun_78ed {
  strings:
    $key_78ed = { 2b 82 [2] 0f 8c [2] 24 a0 [2] 0a 82 [2] 1e 99 [2] 11 83 [2] 0f 9e [2] 0d 9f [2] 16 99 [2] 0a 9e [2] 16 b1 }

  condition:
    any of them
}