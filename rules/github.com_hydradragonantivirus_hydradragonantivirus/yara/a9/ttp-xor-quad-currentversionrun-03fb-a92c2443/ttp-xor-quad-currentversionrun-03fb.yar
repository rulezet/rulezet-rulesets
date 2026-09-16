rule TTP_XOR_QUAD_CurrentVersionRun_03fb {
  strings:
    $key_03fb = { 50 94 [2] 74 9a [2] 5f b6 [2] 71 94 [2] 65 8f [2] 6a 95 [2] 74 88 [2] 76 89 [2] 6d 8f [2] 71 88 [2] 6d a7 }

  condition:
    any of them
}