rule TTP_XOR_MULT_DOSStub_c95a {
  strings:
    $key_c95a = { 9d 32 [2] e9 2a [2] ae 28 [2] e9 39 [2] a7 35 [2] ab 3f [2] bc 34 [2] a7 7a [2] 9a }

  condition:
    any of them
}