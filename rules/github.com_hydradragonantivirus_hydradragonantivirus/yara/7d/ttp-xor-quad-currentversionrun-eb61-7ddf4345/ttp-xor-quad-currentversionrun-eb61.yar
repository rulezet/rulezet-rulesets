rule TTP_XOR_QUAD_CurrentVersionRun_eb61 {
  strings:
    $key_eb61 = { b8 0e [2] 9c 00 [2] b7 2c [2] 99 0e [2] 8d 15 [2] 82 0f [2] 9c 12 [2] 9e 13 [2] 85 15 [2] 99 12 [2] 85 3d }

  condition:
    any of them
}