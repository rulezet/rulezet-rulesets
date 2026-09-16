rule TTP_XOR_MULT_DOSStub_6a82 {
  strings:
    $key_6a82 = { 3e ea [2] 4a f2 [2] 0d f0 [2] 4a e1 [2] 04 ed [2] 08 e7 [2] 1f ec [2] 04 a2 [2] 39 }

  condition:
    any of them
}