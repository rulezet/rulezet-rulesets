rule TTP_XOR_QUAD_CurrentVersionRun_78fb {
  strings:
    $key_78fb = { 2b 94 [2] 0f 9a [2] 24 b6 [2] 0a 94 [2] 1e 8f [2] 11 95 [2] 0f 88 [2] 0d 89 [2] 16 8f [2] 0a 88 [2] 16 a7 }

  condition:
    any of them
}