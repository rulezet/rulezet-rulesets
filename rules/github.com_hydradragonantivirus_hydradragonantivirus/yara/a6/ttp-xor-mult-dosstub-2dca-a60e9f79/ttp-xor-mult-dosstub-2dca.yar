rule TTP_XOR_MULT_DOSStub_2dca {
  strings:
    $key_2dca = { 79 a2 [2] 0d ba [2] 4a b8 [2] 0d a9 [2] 43 a5 [2] 4f af [2] 58 a4 [2] 43 ea [2] 7e }

  condition:
    any of them
}