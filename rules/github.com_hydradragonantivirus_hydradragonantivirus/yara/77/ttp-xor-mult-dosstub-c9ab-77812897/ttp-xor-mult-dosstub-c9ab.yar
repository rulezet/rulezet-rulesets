rule TTP_XOR_MULT_DOSStub_c9ab {
  strings:
    $key_c9ab = { 9d c3 [2] e9 db [2] ae d9 [2] e9 c8 [2] a7 c4 [2] ab ce [2] bc c5 [2] a7 8b [2] 9a }

  condition:
    any of them
}