rule TTP_XOR_QUAD_CurrentVersionRun_73fb {
  strings:
    $key_73fb = { 20 94 [2] 04 9a [2] 2f b6 [2] 01 94 [2] 15 8f [2] 1a 95 [2] 04 88 [2] 06 89 [2] 1d 8f [2] 01 88 [2] 1d a7 }

  condition:
    any of them
}