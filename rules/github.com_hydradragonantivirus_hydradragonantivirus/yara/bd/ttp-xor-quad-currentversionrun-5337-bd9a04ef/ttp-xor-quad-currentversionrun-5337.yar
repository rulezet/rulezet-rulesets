rule TTP_XOR_QUAD_CurrentVersionRun_5337 {
  strings:
    $key_5337 = { 00 58 [2] 24 56 [2] 0f 7a [2] 21 58 [2] 35 43 [2] 3a 59 [2] 24 44 [2] 26 45 [2] 3d 43 [2] 21 44 [2] 3d 6b }

  condition:
    any of them
}