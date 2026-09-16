rule TTP_XOR_QUAD_CurrentVersionRun_eb36 {
  strings:
    $key_eb36 = { b8 59 [2] 9c 57 [2] b7 7b [2] 99 59 [2] 8d 42 [2] 82 58 [2] 9c 45 [2] 9e 44 [2] 85 42 [2] 99 45 [2] 85 6a }

  condition:
    any of them
}