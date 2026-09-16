rule TTP_XOR_MULT_DOSStub_fdcb {
  strings:
    $key_fdcb = { a9 a3 [2] dd bb [2] 9a b9 [2] dd a8 [2] 93 a4 [2] 9f ae [2] 88 a5 [2] 93 eb [2] ae }

  condition:
    any of them
}