rule TTP_XOR_QUAD_CurrentVersionRun_3637 {
  strings:
    $key_3637 = { 65 58 [2] 41 56 [2] 6a 7a [2] 44 58 [2] 50 43 [2] 5f 59 [2] 41 44 [2] 43 45 [2] 58 43 [2] 44 44 [2] 58 6b }

  condition:
    any of them
}