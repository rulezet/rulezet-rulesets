rule TTP_XOR_MULT_DOSStub_c970 {
  strings:
    $key_c970 = { 9d 18 [2] e9 00 [2] ae 02 [2] e9 13 [2] a7 1f [2] ab 15 [2] bc 1e [2] a7 50 [2] 9a }

  condition:
    any of them
}