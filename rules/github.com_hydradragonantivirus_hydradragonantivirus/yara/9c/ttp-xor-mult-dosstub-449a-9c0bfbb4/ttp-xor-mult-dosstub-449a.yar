rule TTP_XOR_MULT_DOSStub_449a {
  strings:
    $key_449a = { 10 f2 [2] 64 ea [2] 23 e8 [2] 64 f9 [2] 2a f5 [2] 26 ff [2] 31 f4 [2] 2a ba [2] 17 }

  condition:
    any of them
}