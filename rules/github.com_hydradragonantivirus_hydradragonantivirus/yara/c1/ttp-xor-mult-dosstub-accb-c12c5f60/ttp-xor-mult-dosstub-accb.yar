rule TTP_XOR_MULT_DOSStub_accb {
  strings:
    $key_accb = { f8 a3 [2] 8c bb [2] cb b9 [2] 8c a8 [2] c2 a4 [2] ce ae [2] d9 a5 [2] c2 eb [2] ff }

  condition:
    any of them
}