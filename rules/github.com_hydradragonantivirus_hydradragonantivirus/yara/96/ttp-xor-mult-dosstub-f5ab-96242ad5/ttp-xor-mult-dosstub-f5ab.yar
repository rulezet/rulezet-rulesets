rule TTP_XOR_MULT_DOSStub_f5ab {
  strings:
    $key_f5ab = { a1 c3 [2] d5 db [2] 92 d9 [2] d5 c8 [2] 9b c4 [2] 97 ce [2] 80 c5 [2] 9b 8b [2] a6 }

  condition:
    any of them
}