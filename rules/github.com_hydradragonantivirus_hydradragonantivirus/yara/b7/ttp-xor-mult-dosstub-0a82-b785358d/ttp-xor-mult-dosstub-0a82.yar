rule TTP_XOR_MULT_DOSStub_0a82 {
  strings:
    $key_0a82 = { 5e ea [2] 2a f2 [2] 6d f0 [2] 2a e1 [2] 64 ed [2] 68 e7 [2] 7f ec [2] 64 a2 [2] 59 }

  condition:
    any of them
}