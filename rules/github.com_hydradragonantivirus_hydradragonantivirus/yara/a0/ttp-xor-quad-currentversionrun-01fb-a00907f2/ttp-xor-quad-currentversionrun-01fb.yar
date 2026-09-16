rule TTP_XOR_QUAD_CurrentVersionRun_01fb {
  strings:
    $key_01fb = { 52 94 [2] 76 9a [2] 5d b6 [2] 73 94 [2] 67 8f [2] 68 95 [2] 76 88 [2] 74 89 [2] 6f 8f [2] 73 88 [2] 6f a7 }

  condition:
    any of them
}