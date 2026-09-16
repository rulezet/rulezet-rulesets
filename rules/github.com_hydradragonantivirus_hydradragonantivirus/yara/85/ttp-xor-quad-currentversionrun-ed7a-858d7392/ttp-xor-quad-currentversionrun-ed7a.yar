rule TTP_XOR_QUAD_CurrentVersionRun_ed7a {
  strings:
    $key_ed7a = { be 15 [2] 9a 1b [2] b1 37 [2] 9f 15 [2] 8b 0e [2] 84 14 [2] 9a 09 [2] 98 08 [2] 83 0e [2] 9f 09 [2] 83 26 }

  condition:
    any of them
}