rule TTP_XOR_QUAD_CurrentVersionRun_eb23 {
  strings:
    $key_eb23 = { b8 4c [2] 9c 42 [2] b7 6e [2] 99 4c [2] 8d 57 [2] 82 4d [2] 9c 50 [2] 9e 51 [2] 85 57 [2] 99 50 [2] 85 7f }

  condition:
    any of them
}