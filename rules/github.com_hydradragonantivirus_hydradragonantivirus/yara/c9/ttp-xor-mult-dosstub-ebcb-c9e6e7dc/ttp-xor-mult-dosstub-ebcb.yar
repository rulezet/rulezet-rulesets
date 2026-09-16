rule TTP_XOR_MULT_DOSStub_ebcb {
  strings:
    $key_ebcb = { bf a3 [2] cb bb [2] 8c b9 [2] cb a8 [2] 85 a4 [2] 89 ae [2] 9e a5 [2] 85 eb [2] b8 }

  condition:
    any of them
}