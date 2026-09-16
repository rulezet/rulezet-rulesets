rule TTP_XOR_MULT_DOSStub_9aab {
  strings:
    $key_9aab = { ce c3 [2] ba db [2] fd d9 [2] ba c8 [2] f4 c4 [2] f8 ce [2] ef c5 [2] f4 8b [2] c9 }

  condition:
    any of them
}