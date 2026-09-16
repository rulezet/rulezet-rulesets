rule TTP_XOR_QUAD_CurrentVersionRun_f372 {
  strings:
    $key_f372 = { a0 1d [2] 84 13 [2] af 3f [2] 81 1d [2] 95 06 [2] 9a 1c [2] 84 01 [2] 86 00 [2] 9d 06 [2] 81 01 [2] 9d 2e }

  condition:
    any of them
}