rule TTP_XOR_QUAD_CurrentVersionRun_a2fb {
  strings:
    $key_a2fb = { f1 94 [2] d5 9a [2] fe b6 [2] d0 94 [2] c4 8f [2] cb 95 [2] d5 88 [2] d7 89 [2] cc 8f [2] d0 88 [2] cc a7 }

  condition:
    any of them
}