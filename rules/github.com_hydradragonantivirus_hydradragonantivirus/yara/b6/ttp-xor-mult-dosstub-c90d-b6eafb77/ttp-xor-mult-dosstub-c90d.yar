rule TTP_XOR_MULT_DOSStub_c90d {
  strings:
    $key_c90d = { 9d 65 [2] e9 7d [2] ae 7f [2] e9 6e [2] a7 62 [2] ab 68 [2] bc 63 [2] a7 2d [2] 9a }

  condition:
    any of them
}