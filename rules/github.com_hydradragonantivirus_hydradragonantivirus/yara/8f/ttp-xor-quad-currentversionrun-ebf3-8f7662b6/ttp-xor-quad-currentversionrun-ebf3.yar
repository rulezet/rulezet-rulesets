rule TTP_XOR_QUAD_CurrentVersionRun_ebf3 {
  strings:
    $key_ebf3 = { b8 9c [2] 9c 92 [2] b7 be [2] 99 9c [2] 8d 87 [2] 82 9d [2] 9c 80 [2] 9e 81 [2] 85 87 [2] 99 80 [2] 85 af }

  condition:
    any of them
}