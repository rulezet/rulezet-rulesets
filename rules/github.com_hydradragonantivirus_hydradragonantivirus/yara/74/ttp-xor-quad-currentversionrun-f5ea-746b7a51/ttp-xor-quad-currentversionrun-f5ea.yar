rule TTP_XOR_QUAD_CurrentVersionRun_f5ea {
  strings:
    $key_f5ea = { a6 85 [2] 82 8b [2] a9 a7 [2] 87 85 [2] 93 9e [2] 9c 84 [2] 82 99 [2] 80 98 [2] 9b 9e [2] 87 99 [2] 9b b6 }

  condition:
    any of them
}