rule TTP_XOR_QUAD_CurrentVersionRun_eb48 {
  strings:
    $key_eb48 = { b8 27 [2] 9c 29 [2] b7 05 [2] 99 27 [2] 8d 3c [2] 82 26 [2] 9c 3b [2] 9e 3a [2] 85 3c [2] 99 3b [2] 85 14 }

  condition:
    any of them
}