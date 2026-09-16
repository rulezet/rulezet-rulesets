rule TTP_XOR_QUAD_CurrentVersionRun_29fb {
  strings:
    $key_29fb = { 7a 94 [2] 5e 9a [2] 75 b6 [2] 5b 94 [2] 4f 8f [2] 40 95 [2] 5e 88 [2] 5c 89 [2] 47 8f [2] 5b 88 [2] 47 a7 }

  condition:
    any of them
}