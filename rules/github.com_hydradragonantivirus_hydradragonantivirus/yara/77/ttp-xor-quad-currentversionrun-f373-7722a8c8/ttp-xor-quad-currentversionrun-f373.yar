rule TTP_XOR_QUAD_CurrentVersionRun_f373 {
  strings:
    $key_f373 = { a0 1c [2] 84 12 [2] af 3e [2] 81 1c [2] 95 07 [2] 9a 1d [2] 84 00 [2] 86 01 [2] 9d 07 [2] 81 00 [2] 9d 2f }

  condition:
    any of them
}