rule TTP_XOR_QUAD_CurrentVersionRun_38fb {
  strings:
    $key_38fb = { 6b 94 [2] 4f 9a [2] 64 b6 [2] 4a 94 [2] 5e 8f [2] 51 95 [2] 4f 88 [2] 4d 89 [2] 56 8f [2] 4a 88 [2] 56 a7 }

  condition:
    any of them
}