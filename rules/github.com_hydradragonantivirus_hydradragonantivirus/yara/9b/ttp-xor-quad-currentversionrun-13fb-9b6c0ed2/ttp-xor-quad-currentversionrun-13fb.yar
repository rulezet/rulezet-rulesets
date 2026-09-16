rule TTP_XOR_QUAD_CurrentVersionRun_13fb {
  strings:
    $key_13fb = { 40 94 [2] 64 9a [2] 4f b6 [2] 61 94 [2] 75 8f [2] 7a 95 [2] 64 88 [2] 66 89 [2] 7d 8f [2] 61 88 [2] 7d a7 }

  condition:
    any of them
}