rule TTP_XOR_QUAD_CurrentVersionRun_fa46 {
  strings:
    $key_fa46 = { a9 29 [2] 8d 27 [2] a6 0b [2] 88 29 [2] 9c 32 [2] 93 28 [2] 8d 35 [2] 8f 34 [2] 94 32 [2] 88 35 [2] 94 1a }

  condition:
    any of them
}