rule TTP_XOR_QUAD_CurrentVersionRun_5fe9 {
  strings:
    $key_5fe9 = { 0c 86 [2] 28 88 [2] 03 a4 [2] 2d 86 [2] 39 9d [2] 36 87 [2] 28 9a [2] 2a 9b [2] 31 9d [2] 2d 9a [2] 31 b5 }

  condition:
    any of them
}