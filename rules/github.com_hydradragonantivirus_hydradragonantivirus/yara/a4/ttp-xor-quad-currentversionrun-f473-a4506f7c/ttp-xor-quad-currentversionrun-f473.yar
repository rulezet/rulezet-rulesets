rule TTP_XOR_QUAD_CurrentVersionRun_f473 {
  strings:
    $key_f473 = { a7 1c [2] 83 12 [2] a8 3e [2] 86 1c [2] 92 07 [2] 9d 1d [2] 83 00 [2] 81 01 [2] 9a 07 [2] 86 00 [2] 9a 2f }

  condition:
    any of them
}