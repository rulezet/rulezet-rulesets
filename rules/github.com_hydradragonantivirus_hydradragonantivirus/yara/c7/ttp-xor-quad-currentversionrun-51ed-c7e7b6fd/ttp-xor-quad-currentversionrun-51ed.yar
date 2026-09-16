rule TTP_XOR_QUAD_CurrentVersionRun_51ed {
  strings:
    $key_51ed = { 02 82 [2] 26 8c [2] 0d a0 [2] 23 82 [2] 37 99 [2] 38 83 [2] 26 9e [2] 24 9f [2] 3f 99 [2] 23 9e [2] 3f b1 }

  condition:
    any of them
}