rule TTP_XOR_QUAD_CurrentVersionRun_48fb {
  strings:
    $key_48fb = { 1b 94 [2] 3f 9a [2] 14 b6 [2] 3a 94 [2] 2e 8f [2] 21 95 [2] 3f 88 [2] 3d 89 [2] 26 8f [2] 3a 88 [2] 26 a7 }

  condition:
    any of them
}