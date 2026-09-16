rule TTP_XOR_MULT_DOSStub_c927 {
  strings:
    $key_c927 = { 9d 4f [2] e9 57 [2] ae 55 [2] e9 44 [2] a7 48 [2] ab 42 [2] bc 49 [2] a7 07 [2] 9a }

  condition:
    any of them
}