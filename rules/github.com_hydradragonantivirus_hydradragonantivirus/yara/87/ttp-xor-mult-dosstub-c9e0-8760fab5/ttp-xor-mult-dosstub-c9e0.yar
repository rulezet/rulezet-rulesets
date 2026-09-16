rule TTP_XOR_MULT_DOSStub_c9e0 {
  strings:
    $key_c9e0 = { 9d 88 [2] e9 90 [2] ae 92 [2] e9 83 [2] a7 8f [2] ab 85 [2] bc 8e [2] a7 c0 [2] 9a }

  condition:
    any of them
}