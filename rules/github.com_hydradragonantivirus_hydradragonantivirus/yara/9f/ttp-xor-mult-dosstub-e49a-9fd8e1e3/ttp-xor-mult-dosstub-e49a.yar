rule TTP_XOR_MULT_DOSStub_e49a {
  strings:
    $key_e49a = { b0 f2 [2] c4 ea [2] 83 e8 [2] c4 f9 [2] 8a f5 [2] 86 ff [2] 91 f4 [2] 8a ba [2] b7 }

  condition:
    any of them
}