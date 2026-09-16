rule TTP_XOR_MULT_DOSStub_c9f0 {
  strings:
    $key_c9f0 = { 9d 98 [2] e9 80 [2] ae 82 [2] e9 93 [2] a7 9f [2] ab 95 [2] bc 9e [2] a7 d0 [2] 9a }

  condition:
    any of them
}