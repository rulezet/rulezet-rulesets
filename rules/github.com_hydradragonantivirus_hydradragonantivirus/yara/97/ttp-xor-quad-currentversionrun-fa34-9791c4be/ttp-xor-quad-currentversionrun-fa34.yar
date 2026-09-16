rule TTP_XOR_QUAD_CurrentVersionRun_fa34 {
  strings:
    $key_fa34 = { a9 5b [2] 8d 55 [2] a6 79 [2] 88 5b [2] 9c 40 [2] 93 5a [2] 8d 47 [2] 8f 46 [2] 94 40 [2] 88 47 [2] 94 68 }

  condition:
    any of them
}