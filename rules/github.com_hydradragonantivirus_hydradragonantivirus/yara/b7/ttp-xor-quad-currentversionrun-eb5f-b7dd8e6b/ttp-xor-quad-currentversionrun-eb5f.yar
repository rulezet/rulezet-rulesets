rule TTP_XOR_QUAD_CurrentVersionRun_eb5f {
  strings:
    $key_eb5f = { b8 30 [2] 9c 3e [2] b7 12 [2] 99 30 [2] 8d 2b [2] 82 31 [2] 9c 2c [2] 9e 2d [2] 85 2b [2] 99 2c [2] 85 03 }

  condition:
    any of them
}