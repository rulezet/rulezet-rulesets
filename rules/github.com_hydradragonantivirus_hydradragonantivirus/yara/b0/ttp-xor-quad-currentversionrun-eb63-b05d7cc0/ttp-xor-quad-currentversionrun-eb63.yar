rule TTP_XOR_QUAD_CurrentVersionRun_eb63 {
  strings:
    $key_eb63 = { b8 0c [2] 9c 02 [2] b7 2e [2] 99 0c [2] 8d 17 [2] 82 0d [2] 9c 10 [2] 9e 11 [2] 85 17 [2] 99 10 [2] 85 3f }

  condition:
    any of them
}