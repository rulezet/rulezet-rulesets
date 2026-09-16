rule TTP_XOR_QUAD_CurrentVersionRun_fa29 {
  strings:
    $key_fa29 = { a9 46 [2] 8d 48 [2] a6 64 [2] 88 46 [2] 9c 5d [2] 93 47 [2] 8d 5a [2] 8f 5b [2] 94 5d [2] 88 5a [2] 94 75 }

  condition:
    any of them
}