rule TTP_XOR_QUAD_CurrentVersionRun_1a59 {
  strings:
    $key_1a59 = { 49 36 [2] 6d 38 [2] 46 14 [2] 68 36 [2] 7c 2d [2] 73 37 [2] 6d 2a [2] 6f 2b [2] 74 2d [2] 68 2a [2] 74 05 }

  condition:
    any of them
}