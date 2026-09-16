rule TTP_XOR_MULT_DOSStub_ef72 {
  strings:
    $key_ef72 = { bb 1a [2] cf 02 [2] 88 00 [2] cf 11 [2] 81 1d [2] 8d 17 [2] 9a 1c [2] 81 52 [2] bc }

  condition:
    any of them
}