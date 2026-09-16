rule TTP_XOR_QUAD_CurrentVersionRun_ed50 {
  strings:
    $key_ed50 = { be 3f [2] 9a 31 [2] b1 1d [2] 9f 3f [2] 8b 24 [2] 84 3e [2] 9a 23 [2] 98 22 [2] 83 24 [2] 9f 23 [2] 83 0c }

  condition:
    any of them
}