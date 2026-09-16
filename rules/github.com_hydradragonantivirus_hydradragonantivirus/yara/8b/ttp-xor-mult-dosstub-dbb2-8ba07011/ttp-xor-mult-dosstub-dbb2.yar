rule TTP_XOR_MULT_DOSStub_dbb2 {
  strings:
    $key_dbb2 = { 8f da [2] fb c2 [2] bc c0 [2] fb d1 [2] b5 dd [2] b9 d7 [2] ae dc [2] b5 92 [2] 88 }

  condition:
    any of them
}