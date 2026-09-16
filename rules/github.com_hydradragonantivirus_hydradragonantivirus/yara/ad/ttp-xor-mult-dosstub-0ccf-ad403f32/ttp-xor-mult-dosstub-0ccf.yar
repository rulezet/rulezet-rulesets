rule TTP_XOR_MULT_DOSStub_0ccf {
  strings:
    $key_0ccf = { 58 a7 [2] 2c bf [2] 6b bd [2] 2c ac [2] 62 a0 [2] 6e aa [2] 79 a1 [2] 62 ef [2] 5f }

  condition:
    any of them
}