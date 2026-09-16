rule TTP_XOR_MULT_DOSStub_c95e {
  strings:
    $key_c95e = { 9d 36 [2] e9 2e [2] ae 2c [2] e9 3d [2] a7 31 [2] ab 3b [2] bc 30 [2] a7 7e [2] 9a }

  condition:
    any of them
}