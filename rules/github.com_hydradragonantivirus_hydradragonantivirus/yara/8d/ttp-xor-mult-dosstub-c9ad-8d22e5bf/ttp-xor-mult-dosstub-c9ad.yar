rule TTP_XOR_MULT_DOSStub_c9ad {
  strings:
    $key_c9ad = { 9d c5 [2] e9 dd [2] ae df [2] e9 ce [2] a7 c2 [2] ab c8 [2] bc c3 [2] a7 8d [2] 9a }

  condition:
    any of them
}