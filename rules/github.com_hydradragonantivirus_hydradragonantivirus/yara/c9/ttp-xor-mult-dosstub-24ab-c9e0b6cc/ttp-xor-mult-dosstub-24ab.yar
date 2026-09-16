rule TTP_XOR_MULT_DOSStub_24ab {
  strings:
    $key_24ab = { 70 c3 [2] 04 db [2] 43 d9 [2] 04 c8 [2] 4a c4 [2] 46 ce [2] 51 c5 [2] 4a 8b [2] 77 }

  condition:
    any of them
}