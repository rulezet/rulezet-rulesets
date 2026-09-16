rule TTP_XOR_MULT_DOSStub_c961 {
  strings:
    $key_c961 = { 9d 09 [2] e9 11 [2] ae 13 [2] e9 02 [2] a7 0e [2] ab 04 [2] bc 0f [2] a7 41 [2] 9a }

  condition:
    any of them
}