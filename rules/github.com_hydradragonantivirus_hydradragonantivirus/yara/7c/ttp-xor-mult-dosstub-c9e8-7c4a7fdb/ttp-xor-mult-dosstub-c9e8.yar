rule TTP_XOR_MULT_DOSStub_c9e8 {
  strings:
    $key_c9e8 = { 9d 80 [2] e9 98 [2] ae 9a [2] e9 8b [2] a7 87 [2] ab 8d [2] bc 86 [2] a7 c8 [2] 9a }

  condition:
    any of them
}