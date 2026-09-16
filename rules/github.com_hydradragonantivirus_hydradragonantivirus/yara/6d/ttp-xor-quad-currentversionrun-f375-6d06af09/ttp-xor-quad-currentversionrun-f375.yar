rule TTP_XOR_QUAD_CurrentVersionRun_f375 {
  strings:
    $key_f375 = { a0 1a [2] 84 14 [2] af 38 [2] 81 1a [2] 95 01 [2] 9a 1b [2] 84 06 [2] 86 07 [2] 9d 01 [2] 81 06 [2] 9d 29 }

  condition:
    any of them
}