rule TTP_XOR_QUAD_CurrentVersionRun_f5e7 {
  strings:
    $key_f5e7 = { a6 88 [2] 82 86 [2] a9 aa [2] 87 88 [2] 93 93 [2] 9c 89 [2] 82 94 [2] 80 95 [2] 9b 93 [2] 87 94 [2] 9b bb }

  condition:
    any of them
}