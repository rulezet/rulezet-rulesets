rule TTP_XOR_QUAD_CurrentVersionRun_5f05 {
  strings:
    $key_5f05 = { 0c 6a [2] 28 64 [2] 03 48 [2] 2d 6a [2] 39 71 [2] 36 6b [2] 28 76 [2] 2a 77 [2] 31 71 [2] 2d 76 [2] 31 59 }

  condition:
    any of them
}