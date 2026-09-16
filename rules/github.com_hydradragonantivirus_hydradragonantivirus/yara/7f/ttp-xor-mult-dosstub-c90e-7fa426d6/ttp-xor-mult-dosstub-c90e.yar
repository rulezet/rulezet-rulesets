rule TTP_XOR_MULT_DOSStub_c90e {
  strings:
    $key_c90e = { 9d 66 [2] e9 7e [2] ae 7c [2] e9 6d [2] a7 61 [2] ab 6b [2] bc 60 [2] a7 2e [2] 9a }

  condition:
    any of them
}