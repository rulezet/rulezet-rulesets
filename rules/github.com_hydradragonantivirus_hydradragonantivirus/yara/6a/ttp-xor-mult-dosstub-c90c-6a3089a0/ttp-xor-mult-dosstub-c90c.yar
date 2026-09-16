rule TTP_XOR_MULT_DOSStub_c90c {
  strings:
    $key_c90c = { 9d 64 [2] e9 7c [2] ae 7e [2] e9 6f [2] a7 63 [2] ab 69 [2] bc 62 [2] a7 2c [2] 9a }

  condition:
    any of them
}