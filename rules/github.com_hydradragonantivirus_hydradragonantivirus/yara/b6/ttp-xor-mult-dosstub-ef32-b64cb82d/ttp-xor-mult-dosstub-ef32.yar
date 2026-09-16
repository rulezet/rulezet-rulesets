rule TTP_XOR_MULT_DOSStub_ef32 {
  strings:
    $key_ef32 = { bb 5a [2] cf 42 [2] 88 40 [2] cf 51 [2] 81 5d [2] 8d 57 [2] 9a 5c [2] 81 12 [2] bc }

  condition:
    any of them
}