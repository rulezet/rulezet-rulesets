rule TTP_XOR_QUAD_CurrentVersionRun_69fb {
  strings:
    $key_69fb = { 3a 94 [2] 1e 9a [2] 35 b6 [2] 1b 94 [2] 0f 8f [2] 00 95 [2] 1e 88 [2] 1c 89 [2] 07 8f [2] 1b 88 [2] 07 a7 }

  condition:
    any of them
}