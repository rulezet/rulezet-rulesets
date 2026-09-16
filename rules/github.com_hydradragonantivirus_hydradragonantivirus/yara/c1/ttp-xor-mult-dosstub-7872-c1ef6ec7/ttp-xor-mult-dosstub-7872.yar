rule TTP_XOR_MULT_DOSStub_7872 {
  strings:
    $key_7872 = { 2c 1a [2] 58 02 [2] 1f 00 [2] 58 11 [2] 16 1d [2] 1a 17 [2] 0d 1c [2] 16 52 [2] 2b }

  condition:
    any of them
}