rule TTP_XOR_MULT_DOSStub_c9f4 {
  strings:
    $key_c9f4 = { 9d 9c [2] e9 84 [2] ae 86 [2] e9 97 [2] a7 9b [2] ab 91 [2] bc 9a [2] a7 d4 [2] 9a }

  condition:
    any of them
}