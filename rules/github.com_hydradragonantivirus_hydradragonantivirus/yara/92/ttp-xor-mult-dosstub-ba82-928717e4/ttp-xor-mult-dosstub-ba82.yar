rule TTP_XOR_MULT_DOSStub_ba82 {
  strings:
    $key_ba82 = { ee ea [2] 9a f2 [2] dd f0 [2] 9a e1 [2] d4 ed [2] d8 e7 [2] cf ec [2] d4 a2 [2] e9 }

  condition:
    any of them
}