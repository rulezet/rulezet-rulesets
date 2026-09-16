rule TTP_XOR_MULT_DOSStub_c91c {
  strings:
    $key_c91c = { 9d 74 [2] e9 6c [2] ae 6e [2] e9 7f [2] a7 73 [2] ab 79 [2] bc 72 [2] a7 3c [2] 9a }

  condition:
    any of them
}