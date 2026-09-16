rule TTP_XOR_MULT_DOSStub_ef43 {
  strings:
    $key_ef43 = { bb 2b [2] cf 33 [2] 88 31 [2] cf 20 [2] 81 2c [2] 8d 26 [2] 9a 2d [2] 81 63 [2] bc }

  condition:
    any of them
}