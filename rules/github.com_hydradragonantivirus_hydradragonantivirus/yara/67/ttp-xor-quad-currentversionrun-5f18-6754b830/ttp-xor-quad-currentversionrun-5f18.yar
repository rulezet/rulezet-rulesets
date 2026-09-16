rule TTP_XOR_QUAD_CurrentVersionRun_5f18 {
  strings:
    $key_5f18 = { 0c 77 [2] 28 79 [2] 03 55 [2] 2d 77 [2] 39 6c [2] 36 76 [2] 28 6b [2] 2a 6a [2] 31 6c [2] 2d 6b [2] 31 44 }

  condition:
    any of them
}