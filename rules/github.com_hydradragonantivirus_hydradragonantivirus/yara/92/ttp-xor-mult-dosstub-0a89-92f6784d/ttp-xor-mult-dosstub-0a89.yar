rule TTP_XOR_MULT_DOSStub_0a89 {
  strings:
    $key_0a89 = { 5e e1 [2] 2a f9 [2] 6d fb [2] 2a ea [2] 64 e6 [2] 68 ec [2] 7f e7 [2] 64 a9 [2] 59 }

  condition:
    any of them
}