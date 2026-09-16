rule TTP_XOR_MULT_DOSStub_c971 {
  strings:
    $key_c971 = { 9d 19 [2] e9 01 [2] ae 03 [2] e9 12 [2] a7 1e [2] ab 14 [2] bc 1f [2] a7 51 [2] 9a }

  condition:
    any of them
}