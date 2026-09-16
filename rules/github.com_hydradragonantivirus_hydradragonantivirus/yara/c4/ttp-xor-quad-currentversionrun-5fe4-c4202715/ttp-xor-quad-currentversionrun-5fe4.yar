rule TTP_XOR_QUAD_CurrentVersionRun_5fe4 {
  strings:
    $key_5fe4 = { 0c 8b [2] 28 85 [2] 03 a9 [2] 2d 8b [2] 39 90 [2] 36 8a [2] 28 97 [2] 2a 96 [2] 31 90 [2] 2d 97 [2] 31 b8 }

  condition:
    any of them
}