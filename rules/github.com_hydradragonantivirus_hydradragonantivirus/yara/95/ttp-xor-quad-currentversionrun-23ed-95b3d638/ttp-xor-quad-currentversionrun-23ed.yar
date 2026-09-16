rule TTP_XOR_QUAD_CurrentVersionRun_23ed {
  strings:
    $key_23ed = { 70 82 [2] 54 8c [2] 7f a0 [2] 51 82 [2] 45 99 [2] 4a 83 [2] 54 9e [2] 56 9f [2] 4d 99 [2] 51 9e [2] 4d b1 }

  condition:
    any of them
}