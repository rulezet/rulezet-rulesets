rule TTP_XOR_MULT_DOSStub_c950 {
  strings:
    $key_c950 = { 9d 38 [2] e9 20 [2] ae 22 [2] e9 33 [2] a7 3f [2] ab 35 [2] bc 3e [2] a7 70 [2] 9a }

  condition:
    any of them
}