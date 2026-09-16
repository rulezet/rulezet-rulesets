rule TTP_XOR_QUAD_CurrentVersionRun_fa7f {
  strings:
    $key_fa7f = { a9 10 [2] 8d 1e [2] a6 32 [2] 88 10 [2] 9c 0b [2] 93 11 [2] 8d 0c [2] 8f 0d [2] 94 0b [2] 88 0c [2] 94 23 }

  condition:
    any of them
}