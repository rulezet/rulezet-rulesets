rule TTP_XOR_QUAD_CurrentVersionRun_ed5a {
  strings:
    $key_ed5a = { be 35 [2] 9a 3b [2] b1 17 [2] 9f 35 [2] 8b 2e [2] 84 34 [2] 9a 29 [2] 98 28 [2] 83 2e [2] 9f 29 [2] 83 06 }

  condition:
    any of them
}