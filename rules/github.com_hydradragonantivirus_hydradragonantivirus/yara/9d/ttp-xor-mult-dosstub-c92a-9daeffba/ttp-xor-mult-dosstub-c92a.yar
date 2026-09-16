rule TTP_XOR_MULT_DOSStub_c92a {
  strings:
    $key_c92a = { 9d 42 [2] e9 5a [2] ae 58 [2] e9 49 [2] a7 45 [2] ab 4f [2] bc 44 [2] a7 0a [2] 9a }

  condition:
    any of them
}