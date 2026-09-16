rule TTP_XOR_QUAD_CurrentVersionRun_f56e {
  strings:
    $key_f56e = { a6 01 [2] 82 0f [2] a9 23 [2] 87 01 [2] 93 1a [2] 9c 00 [2] 82 1d [2] 80 1c [2] 9b 1a [2] 87 1d [2] 9b 32 }

  condition:
    any of them
}