rule TTP_XOR_MULT_DOSStub_c9f5 {
  strings:
    $key_c9f5 = { 9d 9d [2] e9 85 [2] ae 87 [2] e9 96 [2] a7 9a [2] ab 90 [2] bc 9b [2] a7 d5 [2] 9a }

  condition:
    any of them
}