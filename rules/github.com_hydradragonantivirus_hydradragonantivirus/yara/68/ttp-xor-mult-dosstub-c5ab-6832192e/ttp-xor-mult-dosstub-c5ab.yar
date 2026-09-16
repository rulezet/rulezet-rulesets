rule TTP_XOR_MULT_DOSStub_c5ab {
  strings:
    $key_c5ab = { 91 c3 [2] e5 db [2] a2 d9 [2] e5 c8 [2] ab c4 [2] a7 ce [2] b0 c5 [2] ab 8b [2] 96 }

  condition:
    any of them
}