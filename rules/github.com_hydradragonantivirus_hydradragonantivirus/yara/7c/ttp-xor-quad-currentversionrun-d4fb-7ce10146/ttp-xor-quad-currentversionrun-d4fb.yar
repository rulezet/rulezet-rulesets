rule TTP_XOR_QUAD_CurrentVersionRun_d4fb {
  strings:
    $key_d4fb = { 87 94 [2] a3 9a [2] 88 b6 [2] a6 94 [2] b2 8f [2] bd 95 [2] a3 88 [2] a1 89 [2] ba 8f [2] a6 88 [2] ba a7 }

  condition:
    any of them
}