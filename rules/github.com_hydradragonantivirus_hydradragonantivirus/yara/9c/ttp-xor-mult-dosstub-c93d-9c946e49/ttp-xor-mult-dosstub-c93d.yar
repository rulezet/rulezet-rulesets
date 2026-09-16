rule TTP_XOR_MULT_DOSStub_c93d {
  strings:
    $key_c93d = { 9d 55 [2] e9 4d [2] ae 4f [2] e9 5e [2] a7 52 [2] ab 58 [2] bc 53 [2] a7 1d [2] 9a }

  condition:
    any of them
}