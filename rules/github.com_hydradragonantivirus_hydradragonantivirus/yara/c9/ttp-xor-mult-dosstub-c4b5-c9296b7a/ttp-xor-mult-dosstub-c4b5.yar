rule TTP_XOR_MULT_DOSStub_c4b5 {
  strings:
    $key_c4b5 = { 90 dd [2] e4 c5 [2] a3 c7 [2] e4 d6 [2] aa da [2] a6 d0 [2] b1 db [2] aa 95 [2] 97 }

  condition:
    any of them
}