rule TTP_XOR_MULT_DOSStub_c916 {
  strings:
    $key_c916 = { 9d 7e [2] e9 66 [2] ae 64 [2] e9 75 [2] a7 79 [2] ab 73 [2] bc 78 [2] a7 36 [2] 9a }

  condition:
    any of them
}