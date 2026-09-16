rule TTP_XOR_MULT_DOSStub_f6ab {
  strings:
    $key_f6ab = { a2 c3 [2] d6 db [2] 91 d9 [2] d6 c8 [2] 98 c4 [2] 94 ce [2] 83 c5 [2] 98 8b [2] a5 }

  condition:
    any of them
}