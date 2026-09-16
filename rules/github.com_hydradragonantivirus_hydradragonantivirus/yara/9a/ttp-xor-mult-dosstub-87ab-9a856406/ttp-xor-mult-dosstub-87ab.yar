rule TTP_XOR_MULT_DOSStub_87ab {
  strings:
    $key_87ab = { d3 c3 [2] a7 db [2] e0 d9 [2] a7 c8 [2] e9 c4 [2] e5 ce [2] f2 c5 [2] e9 8b [2] d4 }

  condition:
    any of them
}