rule TTP_XOR_QUAD_CurrentVersionRun_f5eb {
  strings:
    $key_f5eb = { a6 84 [2] 82 8a [2] a9 a6 [2] 87 84 [2] 93 9f [2] 9c 85 [2] 82 98 [2] 80 99 [2] 9b 9f [2] 87 98 [2] 9b b7 }

  condition:
    any of them
}