rule TTP_XOR_QUAD_CurrentVersionRun_fa7d {
  strings:
    $key_fa7d = { a9 12 [2] 8d 1c [2] a6 30 [2] 88 12 [2] 9c 09 [2] 93 13 [2] 8d 0e [2] 8f 0f [2] 94 09 [2] 88 0e [2] 94 21 }

  condition:
    any of them
}