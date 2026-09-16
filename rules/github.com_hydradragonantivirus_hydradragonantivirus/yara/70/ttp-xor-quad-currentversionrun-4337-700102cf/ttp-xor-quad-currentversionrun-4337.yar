rule TTP_XOR_QUAD_CurrentVersionRun_4337 {
  strings:
    $key_4337 = { 10 58 [2] 34 56 [2] 1f 7a [2] 31 58 [2] 25 43 [2] 2a 59 [2] 34 44 [2] 36 45 [2] 2d 43 [2] 31 44 [2] 2d 6b }

  condition:
    any of them
}