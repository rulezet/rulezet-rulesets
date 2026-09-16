rule TTP_XOR_MULT_DOSStub_c97c {
  strings:
    $key_c97c = { 9d 14 [2] e9 0c [2] ae 0e [2] e9 1f [2] a7 13 [2] ab 19 [2] bc 12 [2] a7 5c [2] 9a }

  condition:
    any of them
}