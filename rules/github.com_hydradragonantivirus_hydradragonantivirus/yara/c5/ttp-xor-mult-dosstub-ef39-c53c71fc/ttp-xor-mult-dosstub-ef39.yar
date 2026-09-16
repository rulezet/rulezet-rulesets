rule TTP_XOR_MULT_DOSStub_ef39 {
  strings:
    $key_ef39 = { bb 51 [2] cf 49 [2] 88 4b [2] cf 5a [2] 81 56 [2] 8d 5c [2] 9a 57 [2] 81 19 [2] bc }

  condition:
    any of them
}