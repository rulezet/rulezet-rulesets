rule TTP_XOR_MULT_DOSStub_9aa6 {
  strings:
    $key_9aa6 = { ce ce [2] ba d6 [2] fd d4 [2] ba c5 [2] f4 c9 [2] f8 c3 [2] ef c8 [2] f4 86 [2] c9 }

  condition:
    any of them
}