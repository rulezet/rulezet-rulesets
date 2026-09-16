rule TTP_XOR_MULT_DOSStub_ba81 {
  strings:
    $key_ba81 = { ee e9 [2] 9a f1 [2] dd f3 [2] 9a e2 [2] d4 ee [2] d8 e4 [2] cf ef [2] d4 a1 [2] e9 }

  condition:
    any of them
}