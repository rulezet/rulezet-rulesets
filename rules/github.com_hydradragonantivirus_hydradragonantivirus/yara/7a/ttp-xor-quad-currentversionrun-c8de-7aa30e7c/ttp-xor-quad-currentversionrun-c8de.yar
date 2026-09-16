rule TTP_XOR_QUAD_CurrentVersionRun_c8de {
  strings:
    $key_c8de = { 9b b1 [2] bf bf [2] 94 93 [2] ba b1 [2] ae aa [2] a1 b0 [2] bf ad [2] bd ac [2] a6 aa [2] ba ad [2] a6 82 }

  condition:
    any of them
}