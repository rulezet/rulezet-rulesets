rule TTP_XOR_QUAD_CurrentVersionRun_ed5e {
  strings:
    $key_ed5e = { be 31 [2] 9a 3f [2] b1 13 [2] 9f 31 [2] 8b 2a [2] 84 30 [2] 9a 2d [2] 98 2c [2] 83 2a [2] 9f 2d [2] 83 02 }

  condition:
    any of them
}