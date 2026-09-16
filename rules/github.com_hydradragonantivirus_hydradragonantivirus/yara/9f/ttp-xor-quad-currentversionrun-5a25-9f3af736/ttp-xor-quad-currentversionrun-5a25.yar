rule TTP_XOR_QUAD_CurrentVersionRun_5a25 {
  strings:
    $key_5a25 = { 09 4a [2] 2d 44 [2] 06 68 [2] 28 4a [2] 3c 51 [2] 33 4b [2] 2d 56 [2] 2f 57 [2] 34 51 [2] 28 56 [2] 34 79 }

  condition:
    any of them
}