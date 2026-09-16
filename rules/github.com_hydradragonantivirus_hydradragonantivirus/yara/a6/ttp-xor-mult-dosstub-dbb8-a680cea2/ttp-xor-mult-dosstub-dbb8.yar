rule TTP_XOR_MULT_DOSStub_dbb8 {
  strings:
    $key_dbb8 = { 8f d0 [2] fb c8 [2] bc ca [2] fb db [2] b5 d7 [2] b9 dd [2] ae d6 [2] b5 98 [2] 88 }

  condition:
    any of them
}