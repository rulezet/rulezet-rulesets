rule TTP_XOR_QUAD_CurrentVersionRun_6337 {
  strings:
    $key_6337 = { 30 58 [2] 14 56 [2] 3f 7a [2] 11 58 [2] 05 43 [2] 0a 59 [2] 14 44 [2] 16 45 [2] 0d 43 [2] 11 44 [2] 0d 6b }

  condition:
    any of them
}