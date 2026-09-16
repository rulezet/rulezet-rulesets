rule TTP_XOR_MULT_DOSStub_c9ae {
  strings:
    $key_c9ae = { 9d c6 [2] e9 de [2] ae dc [2] e9 cd [2] a7 c1 [2] ab cb [2] bc c0 [2] a7 8e [2] 9a }

  condition:
    any of them
}