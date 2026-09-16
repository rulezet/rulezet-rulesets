rule TTP_XOR_MULT_DOSStub_dbb3 {
  strings:
    $key_dbb3 = { 8f db [2] fb c3 [2] bc c1 [2] fb d0 [2] b5 dc [2] b9 d6 [2] ae dd [2] b5 93 [2] 88 }

  condition:
    any of them
}