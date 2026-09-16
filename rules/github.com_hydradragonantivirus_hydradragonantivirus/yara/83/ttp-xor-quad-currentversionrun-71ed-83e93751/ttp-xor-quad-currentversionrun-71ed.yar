rule TTP_XOR_QUAD_CurrentVersionRun_71ed {
  strings:
    $key_71ed = { 22 82 [2] 06 8c [2] 2d a0 [2] 03 82 [2] 17 99 [2] 18 83 [2] 06 9e [2] 04 9f [2] 1f 99 [2] 03 9e [2] 1f b1 }

  condition:
    any of them
}