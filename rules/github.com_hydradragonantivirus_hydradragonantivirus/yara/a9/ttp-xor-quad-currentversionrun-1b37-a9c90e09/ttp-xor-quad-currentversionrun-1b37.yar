rule TTP_XOR_QUAD_CurrentVersionRun_1b37 {
  strings:
    $key_1b37 = { 48 58 [2] 6c 56 [2] 47 7a [2] 69 58 [2] 7d 43 [2] 72 59 [2] 6c 44 [2] 6e 45 [2] 75 43 [2] 69 44 [2] 75 6b }

  condition:
    any of them
}