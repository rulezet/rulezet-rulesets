rule TTP_XOR_MULT_DOSStub_c9ec {
  strings:
    $key_c9ec = { 9d 84 [2] e9 9c [2] ae 9e [2] e9 8f [2] a7 83 [2] ab 89 [2] bc 82 [2] a7 cc [2] 9a }

  condition:
    any of them
}