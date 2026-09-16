rule TTP_XOR_MULT_DOSStub_dbad {
  strings:
    $key_dbad = { 8f c5 [2] fb dd [2] bc df [2] fb ce [2] b5 c2 [2] b9 c8 [2] ae c3 [2] b5 8d [2] 88 }

  condition:
    any of them
}