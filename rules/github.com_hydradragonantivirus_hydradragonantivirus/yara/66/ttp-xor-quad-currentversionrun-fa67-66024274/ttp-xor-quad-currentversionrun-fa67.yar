rule TTP_XOR_QUAD_CurrentVersionRun_fa67 {
  strings:
    $key_fa67 = { a9 08 [2] 8d 06 [2] a6 2a [2] 88 08 [2] 9c 13 [2] 93 09 [2] 8d 14 [2] 8f 15 [2] 94 13 [2] 88 14 [2] 94 3b }

  condition:
    any of them
}