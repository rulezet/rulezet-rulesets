rule TTP_XOR_MULT_DOSStub_c947 {
  strings:
    $key_c947 = { 9d 2f [2] e9 37 [2] ae 35 [2] e9 24 [2] a7 28 [2] ab 22 [2] bc 29 [2] a7 67 [2] 9a }

  condition:
    any of them
}