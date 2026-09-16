rule TTP_XOR_QUAD_CurrentVersionRun_fa65 {
  strings:
    $key_fa65 = { a9 0a [2] 8d 04 [2] a6 28 [2] 88 0a [2] 9c 11 [2] 93 0b [2] 8d 16 [2] 8f 17 [2] 94 11 [2] 88 16 [2] 94 39 }

  condition:
    any of them
}