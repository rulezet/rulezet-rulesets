rule TTP_XOR_MULT_DOSStub_2582 {
  strings:
    $key_2582 = { 71 ea [2] 05 f2 [2] 42 f0 [2] 05 e1 [2] 4b ed [2] 47 e7 [2] 50 ec [2] 4b a2 [2] 76 }

  condition:
    any of them
}