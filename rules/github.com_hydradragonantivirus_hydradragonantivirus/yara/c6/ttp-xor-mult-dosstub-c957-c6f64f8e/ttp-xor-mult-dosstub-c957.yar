rule TTP_XOR_MULT_DOSStub_c957 {
  strings:
    $key_c957 = { 9d 3f [2] e9 27 [2] ae 25 [2] e9 34 [2] a7 38 [2] ab 32 [2] bc 39 [2] a7 77 [2] 9a }

  condition:
    any of them
}