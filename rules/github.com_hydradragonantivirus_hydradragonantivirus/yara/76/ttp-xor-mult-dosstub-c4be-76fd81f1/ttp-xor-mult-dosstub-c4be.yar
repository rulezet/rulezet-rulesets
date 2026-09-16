rule TTP_XOR_MULT_DOSStub_c4be {
  strings:
    $key_c4be = { 90 d6 [2] e4 ce [2] a3 cc [2] e4 dd [2] aa d1 [2] a6 db [2] b1 d0 [2] aa 9e [2] 97 }

  condition:
    any of them
}