rule TTP_XOR_QUAD_CurrentVersionRun_eb44 {
  strings:
    $key_eb44 = { b8 2b [2] 9c 25 [2] b7 09 [2] 99 2b [2] 8d 30 [2] 82 2a [2] 9c 37 [2] 9e 36 [2] 85 30 [2] 99 37 [2] 85 18 }

  condition:
    any of them
}