rule TTP_XOR_QUAD_CurrentVersionRun_ed5f {
  strings:
    $key_ed5f = { be 30 [2] 9a 3e [2] b1 12 [2] 9f 30 [2] 8b 2b [2] 84 31 [2] 9a 2c [2] 98 2d [2] 83 2b [2] 9f 2c [2] 83 03 }

  condition:
    any of them
}