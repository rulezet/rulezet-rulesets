rule TTP_XOR_QUAD_CurrentVersionRun_fa79 {
  strings:
    $key_fa79 = { a9 16 [2] 8d 18 [2] a6 34 [2] 88 16 [2] 9c 0d [2] 93 17 [2] 8d 0a [2] 8f 0b [2] 94 0d [2] 88 0a [2] 94 25 }

  condition:
    any of them
}