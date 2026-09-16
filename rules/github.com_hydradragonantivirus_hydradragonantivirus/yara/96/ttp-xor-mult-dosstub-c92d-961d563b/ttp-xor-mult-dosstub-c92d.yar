rule TTP_XOR_MULT_DOSStub_c92d {
  strings:
    $key_c92d = { 9d 45 [2] e9 5d [2] ae 5f [2] e9 4e [2] a7 42 [2] ab 48 [2] bc 43 [2] a7 0d [2] 9a }

  condition:
    any of them
}