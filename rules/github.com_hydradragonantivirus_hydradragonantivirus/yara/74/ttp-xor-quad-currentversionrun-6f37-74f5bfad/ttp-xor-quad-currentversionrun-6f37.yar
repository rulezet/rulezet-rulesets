rule TTP_XOR_QUAD_CurrentVersionRun_6f37 {
  strings:
    $key_6f37 = { 3c 58 [2] 18 56 [2] 33 7a [2] 1d 58 [2] 09 43 [2] 06 59 [2] 18 44 [2] 1a 45 [2] 01 43 [2] 1d 44 [2] 01 6b }

  condition:
    any of them
}