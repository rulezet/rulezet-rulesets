rule TTP_XOR_MULT_DOSStub_c482 {
  strings:
    $key_c482 = { 90 ea [2] e4 f2 [2] a3 f0 [2] e4 e1 [2] aa ed [2] a6 e7 [2] b1 ec [2] aa a2 [2] 97 }

  condition:
    any of them
}