rule TTP_XOR_MULT_DOSStub_598f {
  strings:
    $key_598f = { 0d e7 [2] 79 ff [2] 3e fd [2] 79 ec [2] 37 e0 [2] 3b ea [2] 2c e1 [2] 37 af [2] 0a }

  condition:
    any of them
}