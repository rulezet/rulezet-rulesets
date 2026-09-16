rule TTP_XOR_QUAD_CurrentVersionRun_25fb {
  strings:
    $key_25fb = { 76 94 [2] 52 9a [2] 79 b6 [2] 57 94 [2] 43 8f [2] 4c 95 [2] 52 88 [2] 50 89 [2] 4b 8f [2] 57 88 [2] 4b a7 }

  condition:
    any of them
}