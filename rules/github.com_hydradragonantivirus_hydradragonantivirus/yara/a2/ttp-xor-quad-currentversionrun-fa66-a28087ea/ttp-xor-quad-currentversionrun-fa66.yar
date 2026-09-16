rule TTP_XOR_QUAD_CurrentVersionRun_fa66 {
  strings:
    $key_fa66 = { a9 09 [2] 8d 07 [2] a6 2b [2] 88 09 [2] 9c 12 [2] 93 08 [2] 8d 15 [2] 8f 14 [2] 94 12 [2] 88 15 [2] 94 3a }

  condition:
    any of them
}