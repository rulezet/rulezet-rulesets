rule TTP_XOR_MULT_DOSStub_ef60 {
  strings:
    $key_ef60 = { bb 08 [2] cf 10 [2] 88 12 [2] cf 03 [2] 81 0f [2] 8d 05 [2] 9a 0e [2] 81 40 [2] bc }

  condition:
    any of them
}