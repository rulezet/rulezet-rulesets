rule TTP_XOR_QUAD_CurrentVersionRun_4137 {
  strings:
    $key_4137 = { 12 58 [2] 36 56 [2] 1d 7a [2] 33 58 [2] 27 43 [2] 28 59 [2] 36 44 [2] 34 45 [2] 2f 43 [2] 33 44 [2] 2f 6b }

  condition:
    any of them
}