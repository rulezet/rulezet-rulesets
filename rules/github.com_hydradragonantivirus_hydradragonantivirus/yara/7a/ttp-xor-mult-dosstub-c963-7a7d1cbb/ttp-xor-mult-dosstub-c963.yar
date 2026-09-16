rule TTP_XOR_MULT_DOSStub_c963 {
  strings:
    $key_c963 = { 9d 0b [2] e9 13 [2] ae 11 [2] e9 00 [2] a7 0c [2] ab 06 [2] bc 0d [2] a7 43 [2] 9a }

  condition:
    any of them
}