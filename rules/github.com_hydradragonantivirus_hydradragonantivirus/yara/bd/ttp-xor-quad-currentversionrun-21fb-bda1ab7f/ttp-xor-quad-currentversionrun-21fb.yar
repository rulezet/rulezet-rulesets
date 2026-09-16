rule TTP_XOR_QUAD_CurrentVersionRun_21fb {
  strings:
    $key_21fb = { 72 94 [2] 56 9a [2] 7d b6 [2] 53 94 [2] 47 8f [2] 48 95 [2] 56 88 [2] 54 89 [2] 4f 8f [2] 53 88 [2] 4f a7 }

  condition:
    any of them
}