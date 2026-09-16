rule TTP_XOR_QUAD_CurrentVersionRun_ed03 {
  strings:
    $key_ed03 = { be 6c [2] 9a 62 [2] b1 4e [2] 9f 6c [2] 8b 77 [2] 84 6d [2] 9a 70 [2] 98 71 [2] 83 77 [2] 9f 70 [2] 83 5f }

  condition:
    any of them
}