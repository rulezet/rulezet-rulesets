rule TTP_XOR_MULT_DOSStub_c900 {
  strings:
    $key_c900 = { 9d 68 [2] e9 70 [2] ae 72 [2] e9 63 [2] a7 6f [2] ab 65 [2] bc 6e [2] a7 20 [2] 9a }

  condition:
    any of them
}