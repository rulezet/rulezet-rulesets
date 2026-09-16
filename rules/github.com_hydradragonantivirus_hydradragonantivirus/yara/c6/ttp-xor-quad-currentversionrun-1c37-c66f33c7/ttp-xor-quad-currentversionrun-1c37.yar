rule TTP_XOR_QUAD_CurrentVersionRun_1c37 {
  strings:
    $key_1c37 = { 4f 58 [2] 6b 56 [2] 40 7a [2] 6e 58 [2] 7a 43 [2] 75 59 [2] 6b 44 [2] 69 45 [2] 72 43 [2] 6e 44 [2] 72 6b }

  condition:
    any of them
}