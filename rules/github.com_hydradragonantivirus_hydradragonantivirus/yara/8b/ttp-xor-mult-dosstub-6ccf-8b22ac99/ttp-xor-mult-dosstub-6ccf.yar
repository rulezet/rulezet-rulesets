rule TTP_XOR_MULT_DOSStub_6ccf {
  strings:
    $key_6ccf = { 38 a7 [2] 4c bf [2] 0b bd [2] 4c ac [2] 02 a0 [2] 0e aa [2] 19 a1 [2] 02 ef [2] 3f }

  condition:
    any of them
}