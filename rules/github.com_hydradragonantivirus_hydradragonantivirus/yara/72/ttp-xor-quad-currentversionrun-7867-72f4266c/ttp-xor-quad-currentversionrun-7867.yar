rule TTP_XOR_QUAD_CurrentVersionRun_7867 {
  strings:
    $key_7867 = { 2b 08 [2] 0f 06 [2] 24 2a [2] 0a 08 [2] 1e 13 [2] 11 09 [2] 0f 14 [2] 0d 15 [2] 16 13 [2] 0a 14 [2] 16 3b }

  condition:
    any of them
}