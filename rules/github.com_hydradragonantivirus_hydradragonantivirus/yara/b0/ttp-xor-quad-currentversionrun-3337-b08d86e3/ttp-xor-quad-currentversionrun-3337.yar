rule TTP_XOR_QUAD_CurrentVersionRun_3337 {
  strings:
    $key_3337 = { 60 58 [2] 44 56 [2] 6f 7a [2] 41 58 [2] 55 43 [2] 5a 59 [2] 44 44 [2] 46 45 [2] 5d 43 [2] 41 44 [2] 5d 6b }

  condition:
    any of them
}