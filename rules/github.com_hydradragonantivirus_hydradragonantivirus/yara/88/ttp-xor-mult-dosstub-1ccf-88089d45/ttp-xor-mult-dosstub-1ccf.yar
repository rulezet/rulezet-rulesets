rule TTP_XOR_MULT_DOSStub_1ccf {
  strings:
    $key_1ccf = { 48 a7 [2] 3c bf [2] 7b bd [2] 3c ac [2] 72 a0 [2] 7e aa [2] 69 a1 [2] 72 ef [2] 4f }

  condition:
    any of them
}