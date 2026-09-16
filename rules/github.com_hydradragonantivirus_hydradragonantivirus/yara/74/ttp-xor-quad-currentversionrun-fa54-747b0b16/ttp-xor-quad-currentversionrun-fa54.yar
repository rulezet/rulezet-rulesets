rule TTP_XOR_QUAD_CurrentVersionRun_fa54 {
  strings:
    $key_fa54 = { a9 3b [2] 8d 35 [2] a6 19 [2] 88 3b [2] 9c 20 [2] 93 3a [2] 8d 27 [2] 8f 26 [2] 94 20 [2] 88 27 [2] 94 08 }

  condition:
    any of them
}