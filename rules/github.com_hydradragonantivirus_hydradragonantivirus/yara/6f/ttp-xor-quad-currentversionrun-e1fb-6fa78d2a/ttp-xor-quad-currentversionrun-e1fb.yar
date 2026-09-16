rule TTP_XOR_QUAD_CurrentVersionRun_e1fb {
  strings:
    $key_e1fb = { b2 94 [2] 96 9a [2] bd b6 [2] 93 94 [2] 87 8f [2] 88 95 [2] 96 88 [2] 94 89 [2] 8f 8f [2] 93 88 [2] 8f a7 }

  condition:
    any of them
}