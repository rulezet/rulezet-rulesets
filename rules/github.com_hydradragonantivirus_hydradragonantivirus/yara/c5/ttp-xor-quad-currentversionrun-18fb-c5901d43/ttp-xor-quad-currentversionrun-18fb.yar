rule TTP_XOR_QUAD_CurrentVersionRun_18fb {
  strings:
    $key_18fb = { 4b 94 [2] 6f 9a [2] 44 b6 [2] 6a 94 [2] 7e 8f [2] 71 95 [2] 6f 88 [2] 6d 89 [2] 76 8f [2] 6a 88 [2] 76 a7 }

  condition:
    any of them
}