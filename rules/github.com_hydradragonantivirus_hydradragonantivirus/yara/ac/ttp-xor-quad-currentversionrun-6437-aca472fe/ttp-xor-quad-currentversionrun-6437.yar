rule TTP_XOR_QUAD_CurrentVersionRun_6437 {
  strings:
    $key_6437 = { 37 58 [2] 13 56 [2] 38 7a [2] 16 58 [2] 02 43 [2] 0d 59 [2] 13 44 [2] 11 45 [2] 0a 43 [2] 16 44 [2] 0a 6b }

  condition:
    any of them
}