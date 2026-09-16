rule TTP_XOR_QUAD_CurrentVersionRun_ed23 {
  strings:
    $key_ed23 = { be 4c [2] 9a 42 [2] b1 6e [2] 9f 4c [2] 8b 57 [2] 84 4d [2] 9a 50 [2] 98 51 [2] 83 57 [2] 9f 50 [2] 83 7f }

  condition:
    any of them
}