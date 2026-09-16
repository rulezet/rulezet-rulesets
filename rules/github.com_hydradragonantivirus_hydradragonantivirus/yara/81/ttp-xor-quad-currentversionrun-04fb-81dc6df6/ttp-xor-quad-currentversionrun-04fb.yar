rule TTP_XOR_QUAD_CurrentVersionRun_04fb {
  strings:
    $key_04fb = { 57 94 [2] 73 9a [2] 58 b6 [2] 76 94 [2] 62 8f [2] 6d 95 [2] 73 88 [2] 71 89 [2] 6a 8f [2] 76 88 [2] 6a a7 }

  condition:
    any of them
}