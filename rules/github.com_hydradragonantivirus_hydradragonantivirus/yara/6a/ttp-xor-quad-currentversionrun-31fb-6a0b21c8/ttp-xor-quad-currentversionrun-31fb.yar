rule TTP_XOR_QUAD_CurrentVersionRun_31fb {
  strings:
    $key_31fb = { 62 94 [2] 46 9a [2] 6d b6 [2] 43 94 [2] 57 8f [2] 58 95 [2] 46 88 [2] 44 89 [2] 5f 8f [2] 43 88 [2] 5f a7 }

  condition:
    any of them
}