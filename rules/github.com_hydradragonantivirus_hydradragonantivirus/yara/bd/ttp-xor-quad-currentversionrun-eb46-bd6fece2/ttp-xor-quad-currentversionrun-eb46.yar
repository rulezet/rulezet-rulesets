rule TTP_XOR_QUAD_CurrentVersionRun_eb46 {
  strings:
    $key_eb46 = { b8 29 [2] 9c 27 [2] b7 0b [2] 99 29 [2] 8d 32 [2] 82 28 [2] 9c 35 [2] 9e 34 [2] 85 32 [2] 99 35 [2] 85 1a }

  condition:
    any of them
}