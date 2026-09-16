rule TTP_XOR_MULT_DOSStub_c97b {
  strings:
    $key_c97b = { 9d 13 [2] e9 0b [2] ae 09 [2] e9 18 [2] a7 14 [2] ab 1e [2] bc 15 [2] a7 5b [2] 9a }

  condition:
    any of them
}