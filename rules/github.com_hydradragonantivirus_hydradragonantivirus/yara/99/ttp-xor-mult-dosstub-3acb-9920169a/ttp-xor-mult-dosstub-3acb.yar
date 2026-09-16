rule TTP_XOR_MULT_DOSStub_3acb {
  strings:
    $key_3acb = { 6e a3 [2] 1a bb [2] 5d b9 [2] 1a a8 [2] 54 a4 [2] 58 ae [2] 4f a5 [2] 54 eb [2] 69 }

  condition:
    any of them
}