rule TTP_XOR_MULT_DOSStub_c9f6 {
  strings:
    $key_c9f6 = { 9d 9e [2] e9 86 [2] ae 84 [2] e9 95 [2] a7 99 [2] ab 93 [2] bc 98 [2] a7 d6 [2] 9a }

  condition:
    any of them
}