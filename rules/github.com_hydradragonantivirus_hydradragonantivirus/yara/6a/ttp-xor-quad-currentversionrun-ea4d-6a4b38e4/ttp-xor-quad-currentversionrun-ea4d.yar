rule TTP_XOR_QUAD_CurrentVersionRun_ea4d {
  strings:
    $key_ea4d = { b9 22 [2] 9d 2c [2] b6 00 [2] 98 22 [2] 8c 39 [2] 83 23 [2] 9d 3e [2] 9f 3f [2] 84 39 [2] 98 3e [2] 84 11 }

  condition:
    any of them
}