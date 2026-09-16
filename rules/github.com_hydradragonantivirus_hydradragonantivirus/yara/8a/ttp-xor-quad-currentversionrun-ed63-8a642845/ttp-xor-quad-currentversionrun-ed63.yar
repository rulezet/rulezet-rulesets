rule TTP_XOR_QUAD_CurrentVersionRun_ed63 {
  strings:
    $key_ed63 = { be 0c [2] 9a 02 [2] b1 2e [2] 9f 0c [2] 8b 17 [2] 84 0d [2] 9a 10 [2] 98 11 [2] 83 17 [2] 9f 10 [2] 83 3f }

  condition:
    any of them
}