rule TTP_XOR_QUAD_CurrentVersionRun_f0e7 {
  strings:
    $key_f0e7 = { a3 88 [2] 87 86 [2] ac aa [2] 82 88 [2] 96 93 [2] 99 89 [2] 87 94 [2] 85 95 [2] 9e 93 [2] 82 94 [2] 9e bb }

  condition:
    any of them
}