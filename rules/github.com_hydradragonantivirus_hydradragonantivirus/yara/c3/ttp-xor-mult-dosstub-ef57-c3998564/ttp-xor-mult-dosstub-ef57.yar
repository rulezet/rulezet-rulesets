rule TTP_XOR_MULT_DOSStub_ef57 {
  strings:
    $key_ef57 = { bb 3f [2] cf 27 [2] 88 25 [2] cf 34 [2] 81 38 [2] 8d 32 [2] 9a 39 [2] 81 77 [2] bc }

  condition:
    any of them
}