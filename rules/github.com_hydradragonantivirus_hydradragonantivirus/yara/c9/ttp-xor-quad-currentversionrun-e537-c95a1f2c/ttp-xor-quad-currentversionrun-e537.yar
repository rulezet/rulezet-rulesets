rule TTP_XOR_QUAD_CurrentVersionRun_e537 {
  strings:
    $key_e537 = { b6 58 [2] 92 56 [2] b9 7a [2] 97 58 [2] 83 43 [2] 8c 59 [2] 92 44 [2] 90 45 [2] 8b 43 [2] 97 44 [2] 8b 6b }

  condition:
    any of them
}