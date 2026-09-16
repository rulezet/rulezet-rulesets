rule TTP_XOR_MULT_DOSStub_b5ab {
  strings:
    $key_b5ab = { e1 c3 [2] 95 db [2] d2 d9 [2] 95 c8 [2] db c4 [2] d7 ce [2] c0 c5 [2] db 8b [2] e6 }

  condition:
    any of them
}