rule TTP_XOR_MULT_DOSStub_b6ab {
  strings:
    $key_b6ab = { e2 c3 [2] 96 db [2] d1 d9 [2] 96 c8 [2] d8 c4 [2] d4 ce [2] c3 c5 [2] d8 8b [2] e5 }

  condition:
    any of them
}