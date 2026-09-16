rule TTP_XOR_QUAD_CurrentVersionRun_4c37 {
  strings:
    $key_4c37 = { 1f 58 [2] 3b 56 [2] 10 7a [2] 3e 58 [2] 2a 43 [2] 25 59 [2] 3b 44 [2] 39 45 [2] 22 43 [2] 3e 44 [2] 22 6b }

  condition:
    any of them
}