rule TTP_XOR_QUAD_CurrentVersionRun_72fb {
  strings:
    $key_72fb = { 21 94 [2] 05 9a [2] 2e b6 [2] 00 94 [2] 14 8f [2] 1b 95 [2] 05 88 [2] 07 89 [2] 1c 8f [2] 00 88 [2] 1c a7 }

  condition:
    any of them
}