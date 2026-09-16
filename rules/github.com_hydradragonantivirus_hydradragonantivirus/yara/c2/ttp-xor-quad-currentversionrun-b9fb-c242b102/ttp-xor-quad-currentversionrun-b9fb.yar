rule TTP_XOR_QUAD_CurrentVersionRun_b9fb {
  strings:
    $key_b9fb = { ea 94 [2] ce 9a [2] e5 b6 [2] cb 94 [2] df 8f [2] d0 95 [2] ce 88 [2] cc 89 [2] d7 8f [2] cb 88 [2] d7 a7 }

  condition:
    any of them
}