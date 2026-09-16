rule TTP_XOR_QUAD_CurrentVersionRun_17fb {
  strings:
    $key_17fb = { 44 94 [2] 60 9a [2] 4b b6 [2] 65 94 [2] 71 8f [2] 7e 95 [2] 60 88 [2] 62 89 [2] 79 8f [2] 65 88 [2] 79 a7 }

  condition:
    any of them
}