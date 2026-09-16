rule TTP_XOR_MULT_DOSStub_c906 {
  strings:
    $key_c906 = { 9d 6e [2] e9 76 [2] ae 74 [2] e9 65 [2] a7 69 [2] ab 63 [2] bc 68 [2] a7 26 [2] 9a }

  condition:
    any of them
}