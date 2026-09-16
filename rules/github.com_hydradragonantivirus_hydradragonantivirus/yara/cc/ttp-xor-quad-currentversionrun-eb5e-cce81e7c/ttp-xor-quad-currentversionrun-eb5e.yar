rule TTP_XOR_QUAD_CurrentVersionRun_eb5e {
  strings:
    $key_eb5e = { b8 31 [2] 9c 3f [2] b7 13 [2] 99 31 [2] 8d 2a [2] 82 30 [2] 9c 2d [2] 9e 2c [2] 85 2a [2] 99 2d [2] 85 02 }

  condition:
    any of them
}