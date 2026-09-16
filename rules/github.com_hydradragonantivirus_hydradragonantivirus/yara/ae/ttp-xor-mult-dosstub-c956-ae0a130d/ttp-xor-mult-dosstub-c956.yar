rule TTP_XOR_MULT_DOSStub_c956 {
  strings:
    $key_c956 = { 9d 3e [2] e9 26 [2] ae 24 [2] e9 35 [2] a7 39 [2] ab 33 [2] bc 38 [2] a7 76 [2] 9a }

  condition:
    any of them
}