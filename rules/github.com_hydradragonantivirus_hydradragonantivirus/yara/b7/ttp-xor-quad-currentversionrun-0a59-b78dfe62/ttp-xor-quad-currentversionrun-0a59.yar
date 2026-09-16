rule TTP_XOR_QUAD_CurrentVersionRun_0a59 {
  strings:
    $key_0a59 = { 59 36 [2] 7d 38 [2] 56 14 [2] 78 36 [2] 6c 2d [2] 63 37 [2] 7d 2a [2] 7f 2b [2] 64 2d [2] 78 2a [2] 64 05 }

  condition:
    any of them
}