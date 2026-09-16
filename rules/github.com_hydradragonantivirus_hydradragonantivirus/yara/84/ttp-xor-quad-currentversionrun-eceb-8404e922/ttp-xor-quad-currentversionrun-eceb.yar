rule TTP_XOR_QUAD_CurrentVersionRun_eceb {
  strings:
    $key_eceb = { bf 84 [2] 9b 8a [2] b0 a6 [2] 9e 84 [2] 8a 9f [2] 85 85 [2] 9b 98 [2] 99 99 [2] 82 9f [2] 9e 98 [2] 82 b7 }

  condition:
    any of them
}