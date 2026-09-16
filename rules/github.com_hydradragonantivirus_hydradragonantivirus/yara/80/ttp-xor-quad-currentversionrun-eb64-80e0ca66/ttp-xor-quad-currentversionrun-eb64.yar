rule TTP_XOR_QUAD_CurrentVersionRun_eb64 {
  strings:
    $key_eb64 = { b8 0b [2] 9c 05 [2] b7 29 [2] 99 0b [2] 8d 10 [2] 82 0a [2] 9c 17 [2] 9e 16 [2] 85 10 [2] 99 17 [2] 85 38 }

  condition:
    any of them
}