rule TTP_XOR_QUAD_CurrentVersionRun_eb45 {
  strings:
    $key_eb45 = { b8 2a [2] 9c 24 [2] b7 08 [2] 99 2a [2] 8d 31 [2] 82 2b [2] 9c 36 [2] 9e 37 [2] 85 31 [2] 99 36 [2] 85 19 }

  condition:
    any of them
}