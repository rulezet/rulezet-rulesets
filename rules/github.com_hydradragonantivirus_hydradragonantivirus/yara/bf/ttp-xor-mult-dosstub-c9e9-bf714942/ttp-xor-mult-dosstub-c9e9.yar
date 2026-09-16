rule TTP_XOR_MULT_DOSStub_c9e9 {
  strings:
    $key_c9e9 = { 9d 81 [2] e9 99 [2] ae 9b [2] e9 8a [2] a7 86 [2] ab 8c [2] bc 87 [2] a7 c9 [2] 9a }

  condition:
    any of them
}