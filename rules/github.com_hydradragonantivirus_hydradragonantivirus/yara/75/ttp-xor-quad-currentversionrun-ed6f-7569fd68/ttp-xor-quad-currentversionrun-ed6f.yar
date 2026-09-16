rule TTP_XOR_QUAD_CurrentVersionRun_ed6f {
  strings:
    $key_ed6f = { be 00 [2] 9a 0e [2] b1 22 [2] 9f 00 [2] 8b 1b [2] 84 01 [2] 9a 1c [2] 98 1d [2] 83 1b [2] 9f 1c [2] 83 33 }

  condition:
    any of them
}