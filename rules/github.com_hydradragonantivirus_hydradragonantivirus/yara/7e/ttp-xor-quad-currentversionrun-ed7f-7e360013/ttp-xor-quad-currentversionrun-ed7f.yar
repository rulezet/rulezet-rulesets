rule TTP_XOR_QUAD_CurrentVersionRun_ed7f {
  strings:
    $key_ed7f = { be 10 [2] 9a 1e [2] b1 32 [2] 9f 10 [2] 8b 0b [2] 84 11 [2] 9a 0c [2] 98 0d [2] 83 0b [2] 9f 0c [2] 83 23 }

  condition:
    any of them
}