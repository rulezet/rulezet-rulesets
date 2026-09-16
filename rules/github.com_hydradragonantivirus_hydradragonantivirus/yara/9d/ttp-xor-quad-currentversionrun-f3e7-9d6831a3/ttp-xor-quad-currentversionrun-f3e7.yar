rule TTP_XOR_QUAD_CurrentVersionRun_f3e7 {
  strings:
    $key_f3e7 = { a0 88 [2] 84 86 [2] af aa [2] 81 88 [2] 95 93 [2] 9a 89 [2] 84 94 [2] 86 95 [2] 9d 93 [2] 81 94 [2] 9d bb }

  condition:
    any of them
}