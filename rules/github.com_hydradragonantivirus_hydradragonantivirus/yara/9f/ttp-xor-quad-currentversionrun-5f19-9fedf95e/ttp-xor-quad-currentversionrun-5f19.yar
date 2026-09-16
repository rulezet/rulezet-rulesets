rule TTP_XOR_QUAD_CurrentVersionRun_5f19 {
  strings:
    $key_5f19 = { 0c 76 [2] 28 78 [2] 03 54 [2] 2d 76 [2] 39 6d [2] 36 77 [2] 28 6a [2] 2a 6b [2] 31 6d [2] 2d 6a [2] 31 45 }

  condition:
    any of them
}