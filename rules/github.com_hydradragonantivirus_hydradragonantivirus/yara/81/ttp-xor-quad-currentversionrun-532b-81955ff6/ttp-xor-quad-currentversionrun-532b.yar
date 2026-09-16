rule TTP_XOR_QUAD_CurrentVersionRun_532b {
  strings:
    $key_532b = { 00 44 [2] 24 4a [2] 0f 66 [2] 21 44 [2] 35 5f [2] 3a 45 [2] 24 58 [2] 26 59 [2] 3d 5f [2] 21 58 [2] 3d 77 }

  condition:
    any of them
}