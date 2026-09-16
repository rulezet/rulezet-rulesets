rule TTP_XOR_MULT_DOSStub_c9f7 {
  strings:
    $key_c9f7 = { 9d 9f [2] e9 87 [2] ae 85 [2] e9 94 [2] a7 98 [2] ab 92 [2] bc 99 [2] a7 d7 [2] 9a }

  condition:
    any of them
}