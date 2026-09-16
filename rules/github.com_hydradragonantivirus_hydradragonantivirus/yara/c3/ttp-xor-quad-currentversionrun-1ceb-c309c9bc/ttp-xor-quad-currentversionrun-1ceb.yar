rule TTP_XOR_QUAD_CurrentVersionRun_1ceb {
  strings:
    $key_1ceb = { 4f 84 [2] 6b 8a [2] 40 a6 [2] 6e 84 [2] 7a 9f [2] 75 85 [2] 6b 98 [2] 69 99 [2] 72 9f [2] 6e 98 [2] 72 b7 }

  condition:
    any of them
}