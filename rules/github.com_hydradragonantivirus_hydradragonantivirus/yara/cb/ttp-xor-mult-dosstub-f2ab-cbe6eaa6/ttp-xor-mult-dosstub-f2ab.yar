rule TTP_XOR_MULT_DOSStub_f2ab {
  strings:
    $key_f2ab = { a6 c3 [2] d2 db [2] 95 d9 [2] d2 c8 [2] 9c c4 [2] 90 ce [2] 87 c5 [2] 9c 8b [2] a1 }

  condition:
    any of them
}