rule TTP_XOR_QUAD_CurrentVersionRun_73ed {
  strings:
    $key_73ed = { 20 82 [2] 04 8c [2] 2f a0 [2] 01 82 [2] 15 99 [2] 1a 83 [2] 04 9e [2] 06 9f [2] 1d 99 [2] 01 9e [2] 1d b1 }

  condition:
    any of them
}