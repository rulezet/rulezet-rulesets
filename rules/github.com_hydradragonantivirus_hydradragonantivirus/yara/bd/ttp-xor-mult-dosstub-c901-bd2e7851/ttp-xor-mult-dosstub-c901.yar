rule TTP_XOR_MULT_DOSStub_c901 {
  strings:
    $key_c901 = { 9d 69 [2] e9 71 [2] ae 73 [2] e9 62 [2] a7 6e [2] ab 64 [2] bc 6f [2] a7 21 [2] 9a }

  condition:
    any of them
}