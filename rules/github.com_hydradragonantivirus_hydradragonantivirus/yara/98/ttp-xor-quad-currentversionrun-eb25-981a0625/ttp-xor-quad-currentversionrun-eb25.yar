rule TTP_XOR_QUAD_CurrentVersionRun_eb25 {
  strings:
    $key_eb25 = { b8 4a [2] 9c 44 [2] b7 68 [2] 99 4a [2] 8d 51 [2] 82 4b [2] 9c 56 [2] 9e 57 [2] 85 51 [2] 99 56 [2] 85 79 }

  condition:
    any of them
}