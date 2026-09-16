rule TTP_XOR_QUAD_CurrentVersionRun_7637 {
  strings:
    $key_7637 = { 25 58 [2] 01 56 [2] 2a 7a [2] 04 58 [2] 10 43 [2] 1f 59 [2] 01 44 [2] 03 45 [2] 18 43 [2] 04 44 [2] 18 6b }

  condition:
    any of them
}