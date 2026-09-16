rule TTP_XOR_QUAD_CurrentVersionRun_20ed {
  strings:
    $key_20ed = { 73 82 [2] 57 8c [2] 7c a0 [2] 52 82 [2] 46 99 [2] 49 83 [2] 57 9e [2] 55 9f [2] 4e 99 [2] 52 9e [2] 4e b1 }

  condition:
    any of them
}