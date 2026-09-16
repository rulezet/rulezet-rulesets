rule TTP_XOR_MULT_DOSStub_dbc2 {
  strings:
    $key_dbc2 = { 8f aa [2] fb b2 [2] bc b0 [2] fb a1 [2] b5 ad [2] b9 a7 [2] ae ac [2] b5 e2 [2] 88 }

  condition:
    any of them
}