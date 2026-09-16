rule TTP_XOR_MULT_DOSStub_ef42 {
  strings:
    $key_ef42 = { bb 2a [2] cf 32 [2] 88 30 [2] cf 21 [2] 81 2d [2] 8d 27 [2] 9a 2c [2] 81 62 [2] bc }

  condition:
    any of them
}