rule TTP_XOR_MULT_DOSStub_7acb {
  strings:
    $key_7acb = { 2e a3 [2] 5a bb [2] 1d b9 [2] 5a a8 [2] 14 a4 [2] 18 ae [2] 0f a5 [2] 14 eb [2] 29 }

  condition:
    any of them
}