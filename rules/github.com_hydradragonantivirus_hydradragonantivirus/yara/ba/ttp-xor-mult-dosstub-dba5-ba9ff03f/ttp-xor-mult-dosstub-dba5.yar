rule TTP_XOR_MULT_DOSStub_dba5 {
  strings:
    $key_dba5 = { 8f cd [2] fb d5 [2] bc d7 [2] fb c6 [2] b5 ca [2] b9 c0 [2] ae cb [2] b5 85 [2] 88 }

  condition:
    any of them
}