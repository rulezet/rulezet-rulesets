rule TTP_XOR_QUAD_CurrentVersionRun_f46e {
  strings:
    $key_f46e = { a7 01 [2] 83 0f [2] a8 23 [2] 86 01 [2] 92 1a [2] 9d 00 [2] 83 1d [2] 81 1c [2] 9a 1a [2] 86 1d [2] 9a 32 }

  condition:
    any of them
}