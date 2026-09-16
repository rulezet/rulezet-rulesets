rule TTP_XOR_QUAD_CurrentVersionRun_3644 {
  strings:
    $key_3644 = { 65 2b [2] 41 25 [2] 6a 09 [2] 44 2b [2] 50 30 [2] 5f 2a [2] 41 37 [2] 43 36 [2] 58 30 [2] 44 37 [2] 58 18 }

  condition:
    any of them
}