rule TTP_XOR_MULT_DOSStub_1a82 {
  strings:
    $key_1a82 = { 4e ea [2] 3a f2 [2] 7d f0 [2] 3a e1 [2] 74 ed [2] 78 e7 [2] 6f ec [2] 74 a2 [2] 49 }

  condition:
    any of them
}