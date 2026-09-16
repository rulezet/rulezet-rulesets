rule TTP_XOR_MULT_DOSStub_c94c {
  strings:
    $key_c94c = { 9d 24 [2] e9 3c [2] ae 3e [2] e9 2f [2] a7 23 [2] ab 29 [2] bc 22 [2] a7 6c [2] 9a }

  condition:
    any of them
}