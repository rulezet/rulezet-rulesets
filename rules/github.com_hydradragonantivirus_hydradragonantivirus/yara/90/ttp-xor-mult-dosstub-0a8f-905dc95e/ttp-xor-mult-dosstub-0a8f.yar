rule TTP_XOR_MULT_DOSStub_0a8f {
  strings:
    $key_0a8f = { 5e e7 [2] 2a ff [2] 6d fd [2] 2a ec [2] 64 e0 [2] 68 ea [2] 7f e1 [2] 64 af [2] 59 }

  condition:
    any of them
}