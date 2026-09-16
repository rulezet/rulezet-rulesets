rule TTP_XOR_MULT_DOSStub_4bcb {
  strings:
    $key_4bcb = { 1f a3 [2] 6b bb [2] 2c b9 [2] 6b a8 [2] 25 a4 [2] 29 ae [2] 3e a5 [2] 25 eb [2] 18 }

  condition:
    any of them
}