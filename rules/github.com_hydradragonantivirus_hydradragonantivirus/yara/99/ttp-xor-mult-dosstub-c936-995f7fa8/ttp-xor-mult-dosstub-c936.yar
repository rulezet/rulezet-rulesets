rule TTP_XOR_MULT_DOSStub_c936 {
  strings:
    $key_c936 = { 9d 5e [2] e9 46 [2] ae 44 [2] e9 55 [2] a7 59 [2] ab 53 [2] bc 58 [2] a7 16 [2] 9a }

  condition:
    any of them
}