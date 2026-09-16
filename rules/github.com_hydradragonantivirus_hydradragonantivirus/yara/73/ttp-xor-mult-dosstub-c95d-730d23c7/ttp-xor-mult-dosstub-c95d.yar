rule TTP_XOR_MULT_DOSStub_c95d {
  strings:
    $key_c95d = { 9d 35 [2] e9 2d [2] ae 2f [2] e9 3e [2] a7 32 [2] ab 38 [2] bc 33 [2] a7 7d [2] 9a }

  condition:
    any of them
}