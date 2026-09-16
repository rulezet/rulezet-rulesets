rule TTP_XOR_MULT_DOSStub_c97a {
  strings:
    $key_c97a = { 9d 12 [2] e9 0a [2] ae 08 [2] e9 19 [2] a7 15 [2] ab 1f [2] bc 14 [2] a7 5a [2] 9a }

  condition:
    any of them
}