rule TTP_XOR_MULT_DOSStub_ef21 {
  strings:
    $key_ef21 = { bb 49 [2] cf 51 [2] 88 53 [2] cf 42 [2] 81 4e [2] 8d 44 [2] 9a 4f [2] 81 01 [2] bc }

  condition:
    any of them
}