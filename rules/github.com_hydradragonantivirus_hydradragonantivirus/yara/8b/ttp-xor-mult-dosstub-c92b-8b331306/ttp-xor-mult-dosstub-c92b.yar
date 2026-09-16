rule TTP_XOR_MULT_DOSStub_c92b {
  strings:
    $key_c92b = { 9d 43 [2] e9 5b [2] ae 59 [2] e9 48 [2] a7 44 [2] ab 4e [2] bc 45 [2] a7 0b [2] 9a }

  condition:
    any of them
}