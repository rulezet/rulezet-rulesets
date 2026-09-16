rule TTP_XOR_MULT_DOSStub_b78d {
  strings:
    $key_b78d = { e3 e5 [2] 97 fd [2] d0 ff [2] 97 ee [2] d9 e2 [2] d5 e8 [2] c2 e3 [2] d9 ad [2] e4 }

  condition:
    any of them
}