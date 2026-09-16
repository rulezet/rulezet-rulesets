rule TTP_XOR_QUAD_CurrentVersionRun_f377 {
  strings:
    $key_f377 = { a0 18 [2] 84 16 [2] af 3a [2] 81 18 [2] 95 03 [2] 9a 19 [2] 84 04 [2] 86 05 [2] 9d 03 [2] 81 04 [2] 9d 2b }

  condition:
    any of them
}