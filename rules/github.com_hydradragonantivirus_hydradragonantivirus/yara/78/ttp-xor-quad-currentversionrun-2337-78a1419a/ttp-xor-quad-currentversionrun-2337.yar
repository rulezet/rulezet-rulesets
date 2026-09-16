rule TTP_XOR_QUAD_CurrentVersionRun_2337 {
  strings:
    $key_2337 = { 70 58 [2] 54 56 [2] 7f 7a [2] 51 58 [2] 45 43 [2] 4a 59 [2] 54 44 [2] 56 45 [2] 4d 43 [2] 51 44 [2] 4d 6b }

  condition:
    any of them
}