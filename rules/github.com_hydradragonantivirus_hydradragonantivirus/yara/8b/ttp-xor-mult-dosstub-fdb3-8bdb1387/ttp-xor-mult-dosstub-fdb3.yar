rule TTP_XOR_MULT_DOSStub_fdb3 {
  strings:
    $key_fdb3 = { a9 db [2] dd c3 [2] 9a c1 [2] dd d0 [2] 93 dc [2] 9f d6 [2] 88 dd [2] 93 93 [2] ae }

  condition:
    any of them
}