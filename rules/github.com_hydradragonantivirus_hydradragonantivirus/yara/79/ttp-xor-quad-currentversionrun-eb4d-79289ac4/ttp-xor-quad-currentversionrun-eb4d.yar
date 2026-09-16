rule TTP_XOR_QUAD_CurrentVersionRun_eb4d {
  strings:
    $key_eb4d = { b8 22 [2] 9c 2c [2] b7 00 [2] 99 22 [2] 8d 39 [2] 82 23 [2] 9c 3e [2] 9e 3f [2] 85 39 [2] 99 3e [2] 85 11 }

  condition:
    any of them
}