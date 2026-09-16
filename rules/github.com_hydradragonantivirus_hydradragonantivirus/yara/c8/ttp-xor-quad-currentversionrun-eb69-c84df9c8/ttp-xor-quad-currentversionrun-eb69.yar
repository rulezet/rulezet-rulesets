rule TTP_XOR_QUAD_CurrentVersionRun_eb69 {
  strings:
    $key_eb69 = { b8 06 [2] 9c 08 [2] b7 24 [2] 99 06 [2] 8d 1d [2] 82 07 [2] 9c 1a [2] 9e 1b [2] 85 1d [2] 99 1a [2] 85 35 }

  condition:
    any of them
}