rule TTP_XOR_QUAD_CurrentVersionRun_f374 {
  strings:
    $key_f374 = { a0 1b [2] 84 15 [2] af 39 [2] 81 1b [2] 95 00 [2] 9a 1a [2] 84 07 [2] 86 06 [2] 9d 00 [2] 81 07 [2] 9d 28 }

  condition:
    any of them
}