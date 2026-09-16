rule TTP_XOR_MULT_DOSStub_c91a {
  strings:
    $key_c91a = { 9d 72 [2] e9 6a [2] ae 68 [2] e9 79 [2] a7 75 [2] ab 7f [2] bc 74 [2] a7 3a [2] 9a }

  condition:
    any of them
}