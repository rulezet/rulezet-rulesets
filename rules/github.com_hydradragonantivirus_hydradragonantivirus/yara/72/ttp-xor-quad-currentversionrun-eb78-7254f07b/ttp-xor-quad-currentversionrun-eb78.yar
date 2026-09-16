rule TTP_XOR_QUAD_CurrentVersionRun_eb78 {
  strings:
    $key_eb78 = { b8 17 [2] 9c 19 [2] b7 35 [2] 99 17 [2] 8d 0c [2] 82 16 [2] 9c 0b [2] 9e 0a [2] 85 0c [2] 99 0b [2] 85 24 }

  condition:
    any of them
}