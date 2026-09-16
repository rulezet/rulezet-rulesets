rule TTP_XOR_MULT_DOSStub_1bcb {
  strings:
    $key_1bcb = { 4f a3 [2] 3b bb [2] 7c b9 [2] 3b a8 [2] 75 a4 [2] 79 ae [2] 6e a5 [2] 75 eb [2] 48 }

  condition:
    any of them
}