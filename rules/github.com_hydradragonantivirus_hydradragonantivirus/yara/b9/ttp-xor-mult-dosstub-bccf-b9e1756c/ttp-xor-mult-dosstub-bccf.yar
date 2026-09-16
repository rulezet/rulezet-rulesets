rule TTP_XOR_MULT_DOSStub_bccf {
  strings:
    $key_bccf = { e8 a7 [2] 9c bf [2] db bd [2] 9c ac [2] d2 a0 [2] de aa [2] c9 a1 [2] d2 ef [2] ef }

  condition:
    any of them
}