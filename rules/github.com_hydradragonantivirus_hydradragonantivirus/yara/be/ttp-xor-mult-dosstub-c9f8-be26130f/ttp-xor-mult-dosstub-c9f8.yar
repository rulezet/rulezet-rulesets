rule TTP_XOR_MULT_DOSStub_c9f8 {
  strings:
    $key_c9f8 = { 9d 90 [2] e9 88 [2] ae 8a [2] e9 9b [2] a7 97 [2] ab 9d [2] bc 96 [2] a7 d8 [2] 9a }

  condition:
    any of them
}