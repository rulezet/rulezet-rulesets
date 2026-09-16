rule TTP_XOR_MULT_DOSStub_c928 {
  strings:
    $key_c928 = { 9d 40 [2] e9 58 [2] ae 5a [2] e9 4b [2] a7 47 [2] ab 4d [2] bc 46 [2] a7 08 [2] 9a }

  condition:
    any of them
}