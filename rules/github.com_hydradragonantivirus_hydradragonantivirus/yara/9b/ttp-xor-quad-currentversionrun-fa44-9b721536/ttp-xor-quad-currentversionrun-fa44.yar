rule TTP_XOR_QUAD_CurrentVersionRun_fa44 {
  strings:
    $key_fa44 = { a9 2b [2] 8d 25 [2] a6 09 [2] 88 2b [2] 9c 30 [2] 93 2a [2] 8d 37 [2] 8f 36 [2] 94 30 [2] 88 37 [2] 94 18 }

  condition:
    any of them
}