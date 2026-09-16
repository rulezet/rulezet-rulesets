rule TTP_XOR_QUAD_CurrentVersionRun_6c37 {
  strings:
    $key_6c37 = { 3f 58 [2] 1b 56 [2] 30 7a [2] 1e 58 [2] 0a 43 [2] 05 59 [2] 1b 44 [2] 19 45 [2] 02 43 [2] 1e 44 [2] 02 6b }

  condition:
    any of them
}