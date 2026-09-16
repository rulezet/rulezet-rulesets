rule TTP_XOR_MULT_DOSStub_c92c {
  strings:
    $key_c92c = { 9d 44 [2] e9 5c [2] ae 5e [2] e9 4f [2] a7 43 [2] ab 49 [2] bc 42 [2] a7 0c [2] 9a }

  condition:
    any of them
}