rule TTP_XOR_MULT_DOSStub_f0ab {
  strings:
    $key_f0ab = { a4 c3 [2] d0 db [2] 97 d9 [2] d0 c8 [2] 9e c4 [2] 92 ce [2] 85 c5 [2] 9e 8b [2] a3 }

  condition:
    any of them
}