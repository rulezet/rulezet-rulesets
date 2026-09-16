rule TTP_XOR_MULT_DOSStub_c9fc {
  strings:
    $key_c9fc = { 9d 94 [2] e9 8c [2] ae 8e [2] e9 9f [2] a7 93 [2] ab 99 [2] bc 92 [2] a7 dc [2] 9a }

  condition:
    any of them
}