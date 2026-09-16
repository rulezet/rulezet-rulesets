rule TTP_XOR_QUAD_CurrentVersionRun_fa49 {
  strings:
    $key_fa49 = { a9 26 [2] 8d 28 [2] a6 04 [2] 88 26 [2] 9c 3d [2] 93 27 [2] 8d 3a [2] 8f 3b [2] 94 3d [2] 88 3a [2] 94 15 }

  condition:
    any of them
}