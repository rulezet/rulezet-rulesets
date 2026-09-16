rule TTP_XOR_QUAD_CurrentVersionRun_eb07 {
  strings:
    $key_eb07 = { b8 68 [2] 9c 66 [2] b7 4a [2] 99 68 [2] 8d 73 [2] 82 69 [2] 9c 74 [2] 9e 75 [2] 85 73 [2] 99 74 [2] 85 5b }

  condition:
    any of them
}