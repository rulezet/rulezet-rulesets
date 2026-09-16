rule TTP_XOR_MULT_DOSStub_c946 {
  strings:
    $key_c946 = { 9d 2e [2] e9 36 [2] ae 34 [2] e9 25 [2] a7 29 [2] ab 23 [2] bc 28 [2] a7 66 [2] 9a }

  condition:
    any of them
}