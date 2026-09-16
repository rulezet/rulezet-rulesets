rule TTP_XOR_MULT_DOSStub_ebca {
  strings:
    $key_ebca = { bf a2 [2] cb ba [2] 8c b8 [2] cb a9 [2] 85 a5 [2] 89 af [2] 9e a4 [2] 85 ea [2] b8 }

  condition:
    any of them
}