rule TTP_XOR_MULT_DOSStub_5dca {
  strings:
    $key_5dca = { 09 a2 [2] 7d ba [2] 3a b8 [2] 7d a9 [2] 33 a5 [2] 3f af [2] 28 a4 [2] 33 ea [2] 0e }

  condition:
    any of them
}