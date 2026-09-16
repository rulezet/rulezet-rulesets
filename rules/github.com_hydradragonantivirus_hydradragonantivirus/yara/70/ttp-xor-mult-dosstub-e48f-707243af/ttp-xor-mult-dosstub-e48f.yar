rule TTP_XOR_MULT_DOSStub_e48f {
  strings:
    $key_e48f = { b0 e7 [2] c4 ff [2] 83 fd [2] c4 ec [2] 8a e0 [2] 86 ea [2] 91 e1 [2] 8a af [2] b7 }

  condition:
    any of them
}