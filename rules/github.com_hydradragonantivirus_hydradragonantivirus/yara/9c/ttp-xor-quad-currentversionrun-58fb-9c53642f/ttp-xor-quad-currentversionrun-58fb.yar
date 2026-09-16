rule TTP_XOR_QUAD_CurrentVersionRun_58fb {
  strings:
    $key_58fb = { 0b 94 [2] 2f 9a [2] 04 b6 [2] 2a 94 [2] 3e 8f [2] 31 95 [2] 2f 88 [2] 2d 89 [2] 36 8f [2] 2a 88 [2] 36 a7 }

  condition:
    any of them
}