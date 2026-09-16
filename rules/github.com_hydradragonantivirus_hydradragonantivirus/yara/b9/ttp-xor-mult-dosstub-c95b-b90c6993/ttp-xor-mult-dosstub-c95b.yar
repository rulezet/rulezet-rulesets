rule TTP_XOR_MULT_DOSStub_c95b {
  strings:
    $key_c95b = { 9d 33 [2] e9 2b [2] ae 29 [2] e9 38 [2] a7 34 [2] ab 3e [2] bc 35 [2] a7 7b [2] 9a }

  condition:
    any of them
}