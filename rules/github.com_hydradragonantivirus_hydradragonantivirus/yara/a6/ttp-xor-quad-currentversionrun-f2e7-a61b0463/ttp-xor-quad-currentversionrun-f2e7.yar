rule TTP_XOR_QUAD_CurrentVersionRun_f2e7 {
  strings:
    $key_f2e7 = { a1 88 [2] 85 86 [2] ae aa [2] 80 88 [2] 94 93 [2] 9b 89 [2] 85 94 [2] 87 95 [2] 9c 93 [2] 80 94 [2] 9c bb }

  condition:
    any of them
}