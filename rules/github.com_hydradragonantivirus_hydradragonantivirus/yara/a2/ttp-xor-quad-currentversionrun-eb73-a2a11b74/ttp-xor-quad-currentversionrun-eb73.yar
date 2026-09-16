rule TTP_XOR_QUAD_CurrentVersionRun_eb73 {
  strings:
    $key_eb73 = { b8 1c [2] 9c 12 [2] b7 3e [2] 99 1c [2] 8d 07 [2] 82 1d [2] 9c 00 [2] 9e 01 [2] 85 07 [2] 99 00 [2] 85 2f }

  condition:
    any of them
}