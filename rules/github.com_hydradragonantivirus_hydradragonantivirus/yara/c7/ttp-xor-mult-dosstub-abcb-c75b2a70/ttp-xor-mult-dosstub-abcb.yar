rule TTP_XOR_MULT_DOSStub_abcb {
  strings:
    $key_abcb = { ff a3 [2] 8b bb [2] cc b9 [2] 8b a8 [2] c5 a4 [2] c9 ae [2] de a5 [2] c5 eb [2] f8 }

  condition:
    any of them
}