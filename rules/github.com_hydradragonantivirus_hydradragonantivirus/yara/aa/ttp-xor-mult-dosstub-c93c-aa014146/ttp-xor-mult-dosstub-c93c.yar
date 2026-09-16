rule TTP_XOR_MULT_DOSStub_c93c {
  strings:
    $key_c93c = { 9d 54 [2] e9 4c [2] ae 4e [2] e9 5f [2] a7 53 [2] ab 59 [2] bc 52 [2] a7 1c [2] 9a }

  condition:
    any of them
}