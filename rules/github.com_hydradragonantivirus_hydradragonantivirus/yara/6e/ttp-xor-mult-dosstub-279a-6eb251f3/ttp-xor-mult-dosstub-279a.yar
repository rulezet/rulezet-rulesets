rule TTP_XOR_MULT_DOSStub_279a {
  strings:
    $key_279a = { 73 f2 [2] 07 ea [2] 40 e8 [2] 07 f9 [2] 49 f5 [2] 45 ff [2] 52 f4 [2] 49 ba [2] 74 }

  condition:
    any of them
}