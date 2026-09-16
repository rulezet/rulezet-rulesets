rule TTP_XOR_MULT_DOSStub_dbbb {
  strings:
    $key_dbbb = { 8f d3 [2] fb cb [2] bc c9 [2] fb d8 [2] b5 d4 [2] b9 de [2] ae d5 [2] b5 9b [2] 88 }

  condition:
    any of them
}