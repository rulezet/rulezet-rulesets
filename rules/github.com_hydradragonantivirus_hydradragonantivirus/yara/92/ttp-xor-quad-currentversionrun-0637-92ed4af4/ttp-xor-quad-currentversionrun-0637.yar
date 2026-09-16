rule TTP_XOR_QUAD_CurrentVersionRun_0637 {
  strings:
    $key_0637 = { 55 58 [2] 71 56 [2] 5a 7a [2] 74 58 [2] 60 43 [2] 6f 59 [2] 71 44 [2] 73 45 [2] 68 43 [2] 74 44 [2] 68 6b }

  condition:
    any of them
}