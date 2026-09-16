rule TTP_XOR_MULT_DOSStub_6bcb {
  strings:
    $key_6bcb = { 3f a3 [2] 4b bb [2] 0c b9 [2] 4b a8 [2] 05 a4 [2] 09 ae [2] 1e a5 [2] 05 eb [2] 38 }

  condition:
    any of them
}