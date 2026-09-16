rule TTP_XOR_MULT_DOSStub_dbc8 {
  strings:
    $key_dbc8 = { 8f a0 [2] fb b8 [2] bc ba [2] fb ab [2] b5 a7 [2] b9 ad [2] ae a6 [2] b5 e8 [2] 88 }

  condition:
    any of them
}