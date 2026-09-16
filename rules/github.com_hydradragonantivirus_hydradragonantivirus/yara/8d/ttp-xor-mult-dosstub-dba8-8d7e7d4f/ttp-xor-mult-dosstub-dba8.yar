rule TTP_XOR_MULT_DOSStub_dba8 {
  strings:
    $key_dba8 = { 8f c0 [2] fb d8 [2] bc da [2] fb cb [2] b5 c7 [2] b9 cd [2] ae c6 [2] b5 88 [2] 88 }

  condition:
    any of them
}