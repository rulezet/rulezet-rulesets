rule TTP_XOR_QUAD_CurrentVersionRun_41ed {
  strings:
    $key_41ed = { 12 82 [2] 36 8c [2] 1d a0 [2] 33 82 [2] 27 99 [2] 28 83 [2] 36 9e [2] 34 9f [2] 2f 99 [2] 33 9e [2] 2f b1 }

  condition:
    any of them
}