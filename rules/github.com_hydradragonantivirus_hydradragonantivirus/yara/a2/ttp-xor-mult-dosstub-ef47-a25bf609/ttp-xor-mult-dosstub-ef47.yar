rule TTP_XOR_MULT_DOSStub_ef47 {
  strings:
    $key_ef47 = { bb 2f [2] cf 37 [2] 88 35 [2] cf 24 [2] 81 28 [2] 8d 22 [2] 9a 29 [2] 81 67 [2] bc }

  condition:
    any of them
}