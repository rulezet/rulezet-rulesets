rule TTP_XOR_MULT_DOSStub_ef27 {
  strings:
    $key_ef27 = { bb 4f [2] cf 57 [2] 88 55 [2] cf 44 [2] 81 48 [2] 8d 42 [2] 9a 49 [2] 81 07 [2] bc }

  condition:
    any of them
}