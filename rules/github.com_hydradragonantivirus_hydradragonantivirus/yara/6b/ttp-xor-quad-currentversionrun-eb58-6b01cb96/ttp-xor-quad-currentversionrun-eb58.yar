rule TTP_XOR_QUAD_CurrentVersionRun_eb58 {
  strings:
    $key_eb58 = { b8 37 [2] 9c 39 [2] b7 15 [2] 99 37 [2] 8d 2c [2] 82 36 [2] 9c 2b [2] 9e 2a [2] 85 2c [2] 99 2b [2] 85 04 }

  condition:
    any of them
}