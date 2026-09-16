rule TTP_XOR_MULT_DOSStub_dbc5 {
  strings:
    $key_dbc5 = { 8f ad [2] fb b5 [2] bc b7 [2] fb a6 [2] b5 aa [2] b9 a0 [2] ae ab [2] b5 e5 [2] 88 }

  condition:
    any of them
}