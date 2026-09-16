rule TTP_XOR_MULT_DOSStub_c9eb {
  strings:
    $key_c9eb = { 9d 83 [2] e9 9b [2] ae 99 [2] e9 88 [2] a7 84 [2] ab 8e [2] bc 85 [2] a7 cb [2] 9a }

  condition:
    any of them
}