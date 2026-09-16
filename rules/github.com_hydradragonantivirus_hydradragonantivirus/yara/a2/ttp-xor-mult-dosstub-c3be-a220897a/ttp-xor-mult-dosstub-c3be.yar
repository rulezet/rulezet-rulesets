rule TTP_XOR_MULT_DOSStub_c3be {
  strings:
    $key_c3be = { 97 d6 [2] e3 ce [2] a4 cc [2] e3 dd [2] ad d1 [2] a1 db [2] b6 d0 [2] ad 9e [2] 90 }

  condition:
    any of them
}