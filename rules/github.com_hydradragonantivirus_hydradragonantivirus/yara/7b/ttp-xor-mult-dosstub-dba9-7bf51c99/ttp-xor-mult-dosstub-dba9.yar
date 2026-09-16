rule TTP_XOR_MULT_DOSStub_dba9 {
  strings:
    $key_dba9 = { 8f c1 [2] fb d9 [2] bc db [2] fb ca [2] b5 c6 [2] b9 cc [2] ae c7 [2] b5 89 [2] 88 }

  condition:
    any of them
}