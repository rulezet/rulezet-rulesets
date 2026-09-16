rule TTP_XOR_MULT_DOSStub_c925 {
  strings:
    $key_c925 = { 9d 4d [2] e9 55 [2] ae 57 [2] e9 46 [2] a7 4a [2] ab 40 [2] bc 4b [2] a7 05 [2] 9a }

  condition:
    any of them
}