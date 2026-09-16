rule TTP_XOR_MULT_DOSStub_ef77 {
  strings:
    $key_ef77 = { bb 1f [2] cf 07 [2] 88 05 [2] cf 14 [2] 81 18 [2] 8d 12 [2] 9a 19 [2] 81 57 [2] bc }

  condition:
    any of them
}