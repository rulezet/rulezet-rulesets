rule TTP_XOR_QUAD_CurrentVersionRun_59fb {
  strings:
    $key_59fb = { 0a 94 [2] 2e 9a [2] 05 b6 [2] 2b 94 [2] 3f 8f [2] 30 95 [2] 2e 88 [2] 2c 89 [2] 37 8f [2] 2b 88 [2] 37 a7 }

  condition:
    any of them
}