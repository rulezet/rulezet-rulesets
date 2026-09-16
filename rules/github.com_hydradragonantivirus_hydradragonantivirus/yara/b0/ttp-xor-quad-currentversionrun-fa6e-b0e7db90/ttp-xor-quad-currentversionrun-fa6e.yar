rule TTP_XOR_QUAD_CurrentVersionRun_fa6e {
  strings:
    $key_fa6e = { a9 01 [2] 8d 0f [2] a6 23 [2] 88 01 [2] 9c 1a [2] 93 00 [2] 8d 1d [2] 8f 1c [2] 94 1a [2] 88 1d [2] 94 32 }

  condition:
    any of them
}