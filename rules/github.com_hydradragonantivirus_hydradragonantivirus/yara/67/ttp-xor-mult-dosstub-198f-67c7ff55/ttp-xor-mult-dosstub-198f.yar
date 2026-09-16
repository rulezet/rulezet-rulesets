rule TTP_XOR_MULT_DOSStub_198f {
  strings:
    $key_198f = { 4d e7 [2] 39 ff [2] 7e fd [2] 39 ec [2] 77 e0 [2] 7b ea [2] 6c e1 [2] 77 af [2] 4a }

  condition:
    any of them
}