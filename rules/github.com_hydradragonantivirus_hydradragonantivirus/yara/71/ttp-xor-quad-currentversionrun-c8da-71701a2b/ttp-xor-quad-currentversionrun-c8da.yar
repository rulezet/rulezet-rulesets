rule TTP_XOR_QUAD_CurrentVersionRun_c8da {
  strings:
    $key_c8da = { 9b b5 [2] bf bb [2] 94 97 [2] ba b5 [2] ae ae [2] a1 b4 [2] bf a9 [2] bd a8 [2] a6 ae [2] ba a9 [2] a6 86 }

  condition:
    any of them
}