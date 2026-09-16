rule TTP_XOR_QUAD_CurrentVersionRun_2e37 {
  strings:
    $key_2e37 = { 7d 58 [2] 59 56 [2] 72 7a [2] 5c 58 [2] 48 43 [2] 47 59 [2] 59 44 [2] 5b 45 [2] 40 43 [2] 5c 44 [2] 40 6b }

  condition:
    any of them
}