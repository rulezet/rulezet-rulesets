rule TTP_XOR_MULT_DOSStub_eccf {
  strings:
    $key_eccf = { b8 a7 [2] cc bf [2] 8b bd [2] cc ac [2] 82 a0 [2] 8e aa [2] 99 a1 [2] 82 ef [2] bf }

  condition:
    any of them
}