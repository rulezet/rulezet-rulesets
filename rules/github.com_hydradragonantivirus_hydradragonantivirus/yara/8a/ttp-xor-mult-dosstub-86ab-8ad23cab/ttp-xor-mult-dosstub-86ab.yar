rule TTP_XOR_MULT_DOSStub_86ab {
  strings:
    $key_86ab = { d2 c3 [2] a6 db [2] e1 d9 [2] a6 c8 [2] e8 c4 [2] e4 ce [2] f3 c5 [2] e8 8b [2] d5 }

  condition:
    any of them
}