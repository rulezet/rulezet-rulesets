rule TTP_XOR_MULT_DOSStub_02ab {
  strings:
    $key_02ab = { 56 c3 [2] 22 db [2] 65 d9 [2] 22 c8 [2] 6c c4 [2] 60 ce [2] 77 c5 [2] 6c 8b [2] 51 }

  condition:
    any of them
}