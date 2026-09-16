rule TTP_XOR_QUAD_CurrentVersionRun_7837 {
  strings:
    $key_7837 = { 2b 58 [2] 0f 56 [2] 24 7a [2] 0a 58 [2] 1e 43 [2] 11 59 [2] 0f 44 [2] 0d 45 [2] 16 43 [2] 0a 44 [2] 16 6b }

  condition:
    any of them
}