rule TTP_XOR_MULT_DOSStub_c95f {
  strings:
    $key_c95f = { 9d 37 [2] e9 2f [2] ae 2d [2] e9 3c [2] a7 30 [2] ab 3a [2] bc 31 [2] a7 7f [2] 9a }

  condition:
    any of them
}