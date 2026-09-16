rule TTP_XOR_MULT_DOSStub_c94f {
  strings:
    $key_c94f = { 9d 27 [2] e9 3f [2] ae 3d [2] e9 2c [2] a7 20 [2] ab 2a [2] bc 21 [2] a7 6f [2] 9a }

  condition:
    any of them
}