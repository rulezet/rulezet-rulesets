rule TTP_XOR_MULT_DOSStub_c3b5 {
  strings:
    $key_c3b5 = { 97 dd [2] e3 c5 [2] a4 c7 [2] e3 d6 [2] ad da [2] a1 d0 [2] b6 db [2] ad 95 [2] 90 }

  condition:
    any of them
}