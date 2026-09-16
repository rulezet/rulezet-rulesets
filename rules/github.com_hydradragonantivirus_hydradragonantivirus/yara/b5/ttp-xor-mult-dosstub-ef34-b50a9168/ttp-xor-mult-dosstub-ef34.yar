rule TTP_XOR_MULT_DOSStub_ef34 {
  strings:
    $key_ef34 = { bb 5c [2] cf 44 [2] 88 46 [2] cf 57 [2] 81 5b [2] 8d 51 [2] 9a 5a [2] 81 14 [2] bc }

  condition:
    any of them
}