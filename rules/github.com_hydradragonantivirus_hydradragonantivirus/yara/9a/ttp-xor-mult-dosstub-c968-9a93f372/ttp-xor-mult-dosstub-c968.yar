rule TTP_XOR_MULT_DOSStub_c968 {
  strings:
    $key_c968 = { 9d 00 [2] e9 18 [2] ae 1a [2] e9 0b [2] a7 07 [2] ab 0d [2] bc 06 [2] a7 48 [2] 9a }

  condition:
    any of them
}